
rule Backdoor_Linux_Mirai_Z_xp{
	meta:
		description = "Backdoor:Linux/Mirai.Z!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 74 6d 70 2f 6d 6f 6e 6b 65 20 73 65 6c 66 72 65 70 2e 72 6f 75 74 65 72 } //01 00  /tmp/monke selfrep.router
		$a_01_1 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 68 6d 6f 64 20 37 37 37 } //01 00  /bin/busybox chmod 777
		$a_01_2 = {74 6d 70 2f 6d 6f 6e 6b 65 20 2d 72 20 2f } //00 00  tmp/monke -r /
	condition:
		any of ($a_*)
 
}