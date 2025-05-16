####################################################

from router import Router
from packet import Packet
import json

class DVrouter(Router):

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)
        self.heartbeat_time = heartbeat_time
        self.last_time = 0
        self.infinity = 16

        self.ports_to_neighbors = {}

        self.distance_vector = {self.addr: {'cost': 0, 'next_hop_addr': self.addr, 'port': None}}

        self.neighbor_advertised_vectors = {}

        self.forwarding_table = {self.addr: None}

    def handle_packet(self, port, packet):
        if packet.is_traceroute:
            if packet.dst_addr == self.addr:
                return
                
            if packet.dst_addr in self.forwarding_table and self.forwarding_table[packet.dst_addr] is not None:
                output_port = self.forwarding_table[packet.dst_addr]
                self.send(output_port, packet)
        elif packet.kind == Packet.ROUTING:
            try:
                received_dv = json.loads(packet.content)
                if not isinstance(received_dv, dict):
                    return
                
                self.neighbor_advertised_vectors[packet.src_addr] = received_dv
                
                self._recalculate_dv_and_broadcast_if_changed()
            except json.JSONDecodeError:
                pass
            except Exception:
                pass

    def handle_new_link(self, port, endpoint, cost):
        self.ports_to_neighbors[port] = {'neighbor_addr': endpoint, 'link_cost': cost}

        self._recalculate_dv_and_broadcast_if_changed()

    def handle_remove_link(self, port):
        if port in self.ports_to_neighbors:
            removed_neighbor_addr = self.ports_to_neighbors[port]['neighbor_addr']
            
            del self.ports_to_neighbors[port]
            
            if removed_neighbor_addr in self.neighbor_advertised_vectors:
                del self.neighbor_advertised_vectors[removed_neighbor_addr]
            
            self._recalculate_dv_and_broadcast_if_changed()

        else:
            pass

    def handle_time(self, time_ms):
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self._broadcast_dv()

    def _recalculate_dv_and_broadcast_if_changed(self):
        current_dv = {k: v.copy() for k, v in self.distance_vector.items()}
        
        new_dv = {self.addr: {'cost': 0, 'next_hop_addr': self.addr, 'port': None}}
        
        all_destinations = set()
        for neighbor_dv in self.neighbor_advertised_vectors.values():
            all_destinations.update(neighbor_dv.keys())
        all_destinations.update(current_dv.keys())
        all_destinations.add(self.addr)
        for neighbor_info in self.ports_to_neighbors.values():
            all_destinations.add(neighbor_info['neighbor_addr'])

        for dest in all_destinations:
            if dest == self.addr:
                continue

            min_cost_to_dest = self.infinity
            best_next_hop_for_dest = None
            best_port_for_dest = None

            for port_to_neighbor, neighbor_link_info in self.ports_to_neighbors.items():
                current_neighbor_addr = neighbor_link_info['neighbor_addr']
                cost_self_to_current_neighbor = neighbor_link_info['link_cost']
                
                cost_current_neighbor_to_dest = self.infinity
                if current_neighbor_addr == dest:
                    cost_current_neighbor_to_dest = 0
                elif current_neighbor_addr in self.neighbor_advertised_vectors:
                    cost_current_neighbor_to_dest = self.neighbor_advertised_vectors[current_neighbor_addr].get(dest, self.infinity)
                
                total_cost_via_current_neighbor = cost_self_to_current_neighbor + cost_current_neighbor_to_dest
                
                if total_cost_via_current_neighbor < min_cost_to_dest:
                    min_cost_to_dest = total_cost_via_current_neighbor
                    best_next_hop_for_dest = current_neighbor_addr
                    best_port_for_dest = port_to_neighbor
            
            if min_cost_to_dest < self.infinity:
                new_dv[dest] = {
                    'cost': min_cost_to_dest,
                    'next_hop_addr': best_next_hop_for_dest,
                    'port': best_port_for_dest
                }
            elif dest in current_dv:
                new_dv[dest] = {'cost': self.infinity, 'next_hop_addr': None, 'port': None}
        
        if new_dv != current_dv:
            self.distance_vector = new_dv
            self._update_forwarding_table()
            self._broadcast_dv()
            return True
        return False

    def _update_forwarding_table(self):
        self.forwarding_table.clear()
        self.forwarding_table[self.addr] = None
        for dest, info in self.distance_vector.items():
            if dest != self.addr and info.get('port') is not None:
                self.forwarding_table[dest] = info['port']

    def _broadcast_dv(self):
        if not self.ports_to_neighbors:
            return

        for port, neighbor_info in self.ports_to_neighbors.items():
            neighbor_addr = neighbor_info['neighbor_addr']
            dv_to_send = {}

            for dest_addr, dest_info in self.distance_vector.items():
                if dest_info.get('next_hop_addr') == neighbor_addr and dest_addr != neighbor_addr:
                    dv_to_send[dest_addr] = self.infinity
                else:
                    dv_to_send[dest_addr] = dest_info['cost']
            
            packet_content = json.dumps(dv_to_send)
            routing_packet = Packet(kind=Packet.ROUTING, 
                                   src_addr=self.addr, 
                                   dst_addr=neighbor_addr,
                                   content=packet_content)
            
            self.send(port, routing_packet)

    def __repr__(self):
        return f"DVrouter(addr={self.addr})\n  DV: {self.distance_vector}\n  FT: {self.forwarding_table}\n  Neighbors: {self.ports_to_neighbors}"