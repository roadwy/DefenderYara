
rule Backdoor_Linux_BPFDoor_I_MTB{
	meta:
		description = "Backdoor:Linux/BPFDoor.I!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 62 69 6e 2f 72 6d 20 2d 66 20 2f 64 65 76 2f 73 68 6d 2f 25 73 3b 2f 62 69 6e 2f 63 70 20 25 73 20 2f 64 65 76 2f 73 68 6d 2f 25 73 20 26 26 20 2f 62 69 6e 2f 63 68 6d 6f 64 20 37 35 35 20 2f 64 65 76 2f 73 68 6d 2f 25 73 20 26 26 20 2f 64 65 76 2f 73 68 6d 2f 25 73 20 2d 2d 69 6e 69 74 20 26 26 20 2f 62 69 6e 2f 72 6d 20 2d 66 20 2f 64 65 76 2f 73 68 6d 2f 25 73 } //1 /bin/rm -f /dev/shm/%s;/bin/cp %s /dev/shm/%s && /bin/chmod 755 /dev/shm/%s && /dev/shm/%s --init && /bin/rm -f /dev/shm/%s
		$a_01_1 = {2f 73 62 69 6e 2f 69 70 74 61 62 6c 65 73 20 2d 74 20 6e 61 74 20 2d 41 20 50 52 45 52 4f 55 54 49 4e 47 20 2d 70 20 74 63 70 20 2d 73 20 25 73 20 2d 2d 64 70 6f 72 74 20 25 64 20 2d 6a 20 52 45 44 49 52 45 43 54 20 2d 2d 74 6f 2d 70 6f 72 74 73 20 25 64 } //1 /sbin/iptables -t nat -A PREROUTING -p tcp -s %s --dport %d -j REDIRECT --to-ports %d
		$a_01_2 = {45 0f b6 d8 49 01 c3 45 8a 33 44 88 36 41 88 13 02 16 0f b6 d2 8a 14 10 41 30 14 3a } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}