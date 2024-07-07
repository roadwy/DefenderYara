
rule Trojan_Linux_Skidmap_A_MTB{
	meta:
		description = "Trojan:Linux/Skidmap.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {69 70 72 6f 75 74 65 2e 6b 6f 20 6e 65 74 6c 69 6e 6b 2e 6b 6f 20 63 72 79 70 74 6f 76 32 2e 6b 6f } //2 iproute.ko netlink.ko cryptov2.ko
		$a_00_1 = {6b 61 75 64 69 74 65 64 20 6b 73 77 61 70 65 64 20 69 72 71 62 61 6c 61 6e 63 65 64 20 72 63 74 6c 63 6c 69 20 73 79 73 74 65 6d 64 2d 6e 65 74 77 6f 72 6b 20 70 61 6d 64 69 63 6b 73 } //1 kaudited kswaped irqbalanced rctlcli systemd-network pamdicks
		$a_00_2 = {2f 62 69 6e 2f 6d 76 20 70 61 6d 64 69 63 6b 73 2e 6f 72 67 20 2f 74 6d 70 2f 6d 6d 6d } //1 /bin/mv pamdicks.org /tmp/mmm
		$a_00_3 = {2f 74 6d 70 2f 6d 69 6e 65 72 32 } //1 /tmp/miner2
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}