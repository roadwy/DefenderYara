
rule Backdoor_Linux_Mirai_ES_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.ES!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {8e 64 38 f4 00 10 10 80 00 44 10 21 8c 43 00 00 02 20 c8 21 8c 64 00 00 03 20 f8 09 00 00 00 00 26 03 00 01 92 a2 38 f8 30 70 00 ff 02 02 10 2b 8f bc 00 10 14 40 ff f2 } //01 00 
		$a_00_1 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 } //01 00  /bin/busybox
		$a_00_2 = {4b 69 6c 6c 69 6e 67 20 61 6c 6c 20 72 75 6e 6e 69 6e 67 20 61 74 74 61 63 6b 73 } //01 00  Killing all running attacks
		$a_00_3 = {43 6f 6d 6d 69 74 74 69 6e 67 20 53 75 69 63 69 64 65 } //00 00  Committing Suicide
	condition:
		any of ($a_*)
 
}