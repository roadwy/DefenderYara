
rule Backdoor_Linux_Mirai_DX_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.DX!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 42 4f 54 } //5 /bin/busybox BOT
		$a_00_1 = {2f 70 72 6f 63 2f 6e 65 74 2f 74 63 70 } //1 /proc/net/tcp
		$a_00_2 = {2f 63 70 75 69 6e 66 6f } //1 /cpuinfo
		$a_00_3 = {6d 69 73 63 2f 77 61 74 63 68 64 6f 67 } //1 misc/watchdog
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=7
 
}