# LinkLazarus

## 🔍 Packet Handling Strategy in SDN (Ryu Controller)

### 🧠 Overview

In a software-defined networking (SDN) environment, packet handling is more flexible and programmable compared to traditional switches. However, certain behaviors—such as flooding unknown destinations and filtering control-plane traffic—are still essential for maintaining network stability and performance.

This section explains:

- Which packets are dropped and why  
- The recommended packet treatment strategy in SDN  
- What production networks typically do  
- A decision flowchart (ASCII-style) for clarity  

---

### ✅ What Do We Drop and Why?

| **Packet Type**        | **Destination MAC**     | **Why It Exists**                      | **Should We Drop?** | **Reason**                                                                 |
|------------------------|--------------------------|-----------------------------------------|----------------------|-----------------------------------------------------------------------------|
| **LLDP / STP**         | `01:80:c2:00:00:0e`      | Link discovery / loop prevention        | ✅ Yes               | Ryu uses its own topology API. STP isn’t needed in SDN.                    |
| **IPv6 Multicast**     | `33:33:*`                | Router advertisements, mDNS, etc.      | ❌ No (Optional)     | Dropping may break IPv6 support, neighbor discovery, etc.                 |
| **Broadcast**          | `ff:ff:ff:ff:ff:ff`      | ARP, DHCP                               | ❌ No                | Required for IPv4 address resolution (ARP) and basic network functions.   |
| **Unknown Unicast**    | Any                      | Host-to-host before learning MAC        | ❌ No                | We flood initially to learn MACs, then install flows.                     |

---

### ✅ Recommended SDN Packet Strategy

In a well-designed SDN controller:

- **Drop LLDP/STP packets**  
  These are control-plane protocols not needed by the controller.  

- **Allow broadcast and unknown unicast**  
  These are essential for network bootstrapping and ARP resolution.  

- **Install flows when destination MAC is known**  
  This ensures future packets go via the fast data plane.  

---

### 📊 What Happens in a Well-Designed Network?

- Hosts send ARP or ping → controller gets `PacketIn`.  
- Destination MAC not in table → **flood** happens.  
- Controller learns source and destination MACs → **flow is installed**.  
- Future packets use the data plane path, bypassing controller.  
- **Flooding stops naturally** after learning phase.  

> ⚠️ Flooding is **not a bug**. It's a temporary and expected behavior for MAC learning.

---

### 🧭 Decision Flowchart

```text
                ┌───────────────┐
                │   Packet In   │
                └──────┬────────┘
                       │
         ┌─────────────┴─────────────┐
         │                           │
   Is it LLDP/STP?          Is it other type?
         │                           │
      [DROP]                    Proceed to check
                                     │
                       ┌────────────┴────────────┐
                       │                         │
            Is destination MAC known?   →   No → Flood
                       │                         │
                      Yes                        │
                       │                         ▼
            Is flow already installed?   [Send PacketOut + Install Flow]
                       │
                 ┌─────┴─────┐
                 │           │
               Yes          No
                 │           │
               [Ignore]   [Install Flow]
```

---

### ✅ Summary

- ✅ Flooding is **expected** only before learning MAC addresses.  
- ✅ **Filter only LLDP/STP** packets to reduce noise and loops.  
- ✅ **Do not drop** broadcast, unknown unicast, or IPv6 multicast unless necessary.  
- ✅ Focus on **learning quickly**, installing flows, and keeping the controller light.
