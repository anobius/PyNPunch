from scapy.all import *
from socket import *
from time import time, sleep
from sys import platform as PLATFORM


def sendSimpleUDP(dst_ip,src_port,dst_port,content,ttl=64):
    send(IP(dst=dst_ip, ttl=ttl) / UDP(sport=src_port,dport=dst_port) / Raw(load=content))

class peer(object):
    DELTA_TIME = 16;

    def __init__(self,seed,ip_peer):
        '''

        :param seed: a short used to identify what port to use for an attempt. (Peer-pair must have the same seed)
        :param ip_peer: Peer to connect with
        '''
        self.__seed = seed;
        self.__ip_peer = gethostbyname(ip_peer);

    def doPortPunchNegotiation(self,hop_cutoff=4,static_sport=None,static_dport=None):
        '''
        Do a punch attempt
        :param hop_cutoff: number of hops the dummy packet would travel. Must not reach destination
        :param static_sport: source port if applicable
        :param static_dport: destination port if applicable
        :return: (local port, destination port)
        '''
        sleep_time = self.DELTA_TIME / 3;
        seed=self.__seed;
        ip_peer=self.__ip_peer;

        try_port = ( ( int(time()) / 16*seed ) % 25000) + 25000;
        sport = static_sport if static_sport else try_port;
        dport = static_dport if static_dport else try_port;
        print "try port: %d" % try_port;
        print "sport: %s" % sport;
        print "dport: %s" % dport;

        self.reservePortTemp(sport,dport,ttl);
        print "sent falloff packet.. rest timeframe";
        sleep(sleep_time);

        try:
            return self.sendHello(sport,dport,mode=0);
        except Exception as e:
            print "Bind failed: %s, doing scapy mode"
            return self.sendHello(sport,dport,mode=1);

    def findPunchable(self, port=None, mode=0, retry_count=5):
        '''
        Find an available port for use.
        :param port: If specified, port mapping will be asymmetric (one static, one dynamic)
        :param mode: In asymmetric mode; 0 for static source port, 1 for static destination port
        :param retry_count: Number of retries before finally failing.
        :return: (source port, destination port)
        '''
        x = self.DELTA_TIME;
        for i in range(0, retry_count):
            timenow = time();
            sleep_time = (((int(timenow + x) / x)) - (((timenow) / float(x)))) * x;
            print "starting in %.2f seconds" % sleep_time;
            sleep(sleep_time);
            if not port:
                portRes = self.doPortPunchNegotiation();
            else:
                portRes = self.doPortPunchNegotiation(static_sport=port) if mode == 0 else self.doPortPunchNegotiation(static_dport=port) if mode == 1 else self.doPortPunchNegotiation(static_sport=port,static_dport=port);
            if portRes:
                return portRes;
        return None;


    def reservePortTemp(self,sport,dport,hop_cutoff=4):
        '''
        Send a low-ttl packet to have the mapping created on a router's connection tracking table without the packet reaching the destination
        :param sport: source port
        :param dport: destination port
        :param hop_cutoff: ttl
        :return:
        '''
        send(IP(dst=self.__ip_peer, ttl=hop_cutoff) / UDP(sport=sport, dport=dport) / Raw(load="\x00\x00"),verbose=False);
        
    def sendHello(self,sport,dport,mode=0):
        '''
        Shitty handshake
        :param sport: source port
        :param dport: destination port
        :param mode: 0 for bind mode, 1 for scapy mode
        :return: (source port, destination port)
        '''
        
        ip_peer=self.__ip_peer;
        sleep_time = self.DELTA_TIME / 3;
        print "attempting handshake..";
        if mode==0:
            s = socket(AF_INET, SOCK_DGRAM);
            s.settimeout(sleep_time);
            s.bind(("0.0.0.0", sport));
            try:
                s.sendto("hello", (ip_peer, dport));
                data = s.recv(5);
                s.sendto("hello", (ip_peer, dport));
                print data
                if data == "hello":
                    s.sendto("hello", (ip_peer, dport));
                    return sport, dport;
                else:
                    print "HUH?"  # todo: ignore unknown payload, wait until correct one is found
                return None;
            except Exception as e:
                print "Exception: %s" % e;
                print "No message received!"
                return None;
            finally:
                s.close();
                
        elif mode==1:
            #todo: block packet from reaching application layer
            if "linux" in PLATFORM:
                #todo: iptables block
                pass;

            hello = (IP(dst=ip_peer) / UDP(sport=sport, dport=dport) / Raw(load="hello"));
            result = sr(hello,timeout=sleep_time,verbose=False,filter="udp");
            send(hello);
            if len(result[0]) == 0:
                print "timeout..handshake timeframe missed"
                return None;

            if result[0][0][0][Raw].load == "hello":
                #print result[0][0]
                send(hello);
                return sport,dport;#,result;
            else:
                print "HUH?"#todo: ignore unknown payload, wait until correct one is found
                return None;
