
rule Backdoor_Linux_Mirai_V_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.V!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 74 65 6c 6e 65 74 64 20 2d 70 20 39 37 33 31 20 2d 6c 20 2f 62 69 6e 2f 73 68 } //01 00  /bin/busybox telnetd -p 9731 -l /bin/sh
		$a_00_1 = {44 56 52 42 4f 54 } //01 00  DVRBOT
		$a_00_2 = {56 4e 68 55 52 40 4d } //01 00  VNhUR@M
		$a_00_3 = {2f 70 72 6f 63 2f 63 70 75 69 6e 66 6f } //00 00  /proc/cpuinfo
	condition:
		any of ($a_*)
 
}