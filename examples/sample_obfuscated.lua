-- Simulated Prometheus-style obfuscated Lua script for testing
local _0x1234 = {"Hello", " ", "World", "!"}
local function _0x5678(s, seed)
    local r = ""
    for i=1,#s do
        r = r .. string.char(string.byte(s,i) ~ seed)
    end
    return r
end
local msg = "\x48\x65\x6c\x6c\x6f"
print(_0x5678(msg, 0))
print(_0x1234[1] .. _0x1234[2] .. _0x1234[3] .. _0x1234[4])
pcall(function() print("tamper") end)
debug.getinfo(1)
