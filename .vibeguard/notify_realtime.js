let createClient;
try {
  createClient = require("@supabase/supabase-js").createClient;
} catch {
  try {
    const path = require("path");
    createClient = require(path.resolve(process.cwd(), "node_modules/@supabase/supabase-js")).createClient;
  } catch {
    try {
      const path = require("path");
      createClient = require(path.resolve(__dirname, "../frontend/node_modules/@supabase/supabase-js")).createClient;
    } catch {
      console.warn("@supabase/supabase-js not found in current directory or frontend");
      process.exit(1);
    }
  }
}

const SUPABASE_URL =
  process.env.SUPABASE_URL ||
  process.env.VITE_SUPABASE_URL ||
  "https://odqoobyxovzqzxhevnaq.supabase.co";
const SUPABASE_KEY =
  process.env.SUPABASE_KEY ||
  process.env.VITE_SUPABASE_ANON_KEY ||
  "sb_publishable_RvzfDniw_RHlWszb-Con3w_ujbl6e_M";

async function main() {
  const arg = process.argv[2];
  if (!arg) {
    console.error("Missing payload argument");
    process.exit(1);
  }

  let payload;
  try {
    if (arg.startsWith("{")) {
      payload = JSON.parse(arg);
    } else {
      payload = JSON.parse(Buffer.from(arg, "base64").toString("utf-8"));
    }
  } catch (err) {
    console.error("Error parsing payload:", err.message);
    process.exit(1);
  }

  console.log("Broadcasting incident:", payload.id, payload.type);
  const client = createClient(SUPABASE_URL, SUPABASE_KEY);
  const channel = client.channel("vibeguard_live_interceptions");

  channel.subscribe(async (status) => {
    if (status === "SUBSCRIBED") {
      try {
        await channel.send({
          type: "broadcast",
          event: "live_incident",
          payload,
        });
        console.log("Realtime broadcast delivered:", payload.id);
      } catch (err) {
        console.error("Broadcast failed:", err);
      } finally {
        setTimeout(async () => {
          try {
            await client.removeChannel(channel);
          } catch {}
          process.exit(0);
        }, 1200);
      }
    }
  });

  setTimeout(() => {
    console.warn("Realtime timeout (exiting)");
    process.exit(0);
  }, 4000);
}

main().catch(() => process.exit(0));
