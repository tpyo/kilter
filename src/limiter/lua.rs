use redis::Script;
use std::sync::LazyLock;

// Static Lua scripts

pub static SLIDING_WINDOW: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r"
        redis.replicate_commands()

        local key = KEYS[1]
        local max = tonumber(ARGV[1])
        local interval = tonumber(ARGV[2])
        local expiry = tonumber(ARGV[3])

        -- Use Redis server time for consistency with microsecond precision
        local time = redis.call('TIME')
        local now_seconds = tonumber(time[1])
        local now_micros = tonumber(time[2])
        local now = now_seconds + (now_micros / 1000000)
        local window_start = now_seconds - interval

        -- Remove old entries outside the window
        redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

        -- Count current entries in window
        local count = redis.call('ZCARD', key)

        -- Check if limit reached before adding
        if count >= max then
            return {count, 1, now_seconds, now_seconds + interval}
        end

        -- Add new entry with seconds as score (for window) and full timestamp as member (for uniqueness)
        redis.call('ZADD', key, now_seconds, now)
        redis.call('EXPIRE', key, expiry)

        return {count + 1, 0, now_seconds, now_seconds + interval}
        ",
    )
});

pub static FIXED_WINDOW: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r"
        redis.replicate_commands()

        local key_prefix = KEYS[1]
        local max = tonumber(ARGV[1])
        local interval = tonumber(ARGV[2])
        local expiry = tonumber(ARGV[3])

        -- Use Redis server time for consistency
        local time = redis.call('TIME')
        local now = tonumber(time[1])

        -- Calculate the current window and build the key
        local window = math.floor(now / interval)
        local redis_key = key_prefix .. window
        local reset_at = (window + 1) * interval
        local retry_after = reset_at - now

        local current = redis.call('GET', redis_key)
        if current and tonumber(current) >= max then
            return {tonumber(current), 1, reset_at, retry_after}
        end

        if current then
            local count = redis.call('INCR', redis_key)
            return {count, 0, reset_at, retry_after}
        else
            redis.call('SET', redis_key, 1, 'EX', expiry)
            return {1, 0, reset_at, retry_after}
        end
        ",
    )
});

pub static TOKEN_BUCKET: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r"
        redis.replicate_commands()

        local key = KEYS[1]
        local max_tokens = tonumber(ARGV[1])
        local refill_rate = tonumber(ARGV[2])
        local expiry = tonumber(ARGV[3])
        local cost = 1

        -- Use Redis server time for consistency
        local time = redis.call('TIME')
        local now = tonumber(time[1]) + (tonumber(time[2]) / 1000000)

        local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
        local tokens = tonumber(bucket[1])
        local last_refill = tonumber(bucket[2])

        if tokens == nil then
            tokens = max_tokens
            last_refill = now
        end

        -- Refill tokens based on time elapsed. Clamp elapsed to 0 to guard against
        -- wall-clock steps backward (e.g. NTP adjustment), which would otherwise drain tokens.
        local elapsed = math.max(0, now - last_refill)
        tokens = math.min(max_tokens, tokens + (elapsed * refill_rate))

        local allowed = 0
        if tokens >= cost then
            tokens = tokens - cost
            allowed = 1
        end

        -- Update the bucket
        redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
        redis.call('EXPIRE', key, expiry)

        -- Calculate retry_after (seconds until 1 token available)
        local retry_after = 0
        if allowed == 0 then
            retry_after = math.ceil((cost - tokens) / refill_rate)
        end

        return {allowed, math.floor(tokens), retry_after, math.floor(now)}
        ",
    )
});

pub static GCRA: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r"
        redis.replicate_commands()

        local rate_limit_key = KEYS[1]
        local emission_interval = tonumber(ARGV[1])
        local burst_offset = tonumber(ARGV[2])
        local tat_increment = tonumber(ARGV[3])
        local cost = tonumber(ARGV[4])

        -- Get Redis server time with microsecond precision.
        -- Subtract a fixed epoch (2026-01-01) to reduce the magnitude of the timestamp
        -- before adding microseconds as a fraction. Lua uses IEEE 754 doubles (53-bit
        -- integer precision), so a smaller base value preserves more fractional precision.
        -- The offset is added back before returning so callers receive standard Unix timestamps.
        local redis_now = redis.call('TIME')
        local jan_1_2026 = 1767225600
        local now = (redis_now[1] - jan_1_2026) + (redis_now[2] / 1000000)

        -- Get or initialize TAT (Theoretical Arrival Time)
        local tat = redis.call('GET', rate_limit_key)
        if not tat then
            tat = now
        else
            tat = tonumber(tat)
        end

        -- Calculate new TAT and allow_at time
        local new_tat = math.max(tat, now) + tat_increment
        local allow_at = new_tat - burst_offset

        local limited
        local remaining
        local retry_after
        local reset_after

        if allow_at > now then
            -- Rate limited. Clamp remaining to 0: when a client is far over the limit,
            -- (now - tat + burst_offset) can be negative, which would produce a confusing
            -- negative remaining count.
            limited = 1
            remaining = math.max(0, math.floor((now - tat + burst_offset) / emission_interval))
            retry_after = math.ceil(allow_at - now)
            reset_after = math.ceil(new_tat - now)
        else
            -- Allowed
            limited = 0
            remaining = math.floor((now - allow_at) / emission_interval)
            retry_after = 0
            reset_after = math.ceil(new_tat - now)

            -- Update TAT with minimum expiry of 1 second
            local expiry = math.max(1, math.ceil(reset_after + burst_offset))
            redis.call('SET', rate_limit_key, new_tat, 'EX', expiry)
        end

        return {limited, remaining, retry_after, reset_after, math.floor(now + jan_1_2026)}
        ",
    )
});
