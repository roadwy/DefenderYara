
rule Backdoor_Linux_Mirai_EZ_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.EZ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {10 c0 00 09 00 80 10 21 00 86 30 21 90 a2 00 00 00 00 00 00 a0 82 00 00 24 84 00 01 14 86 ff fb 24 a5 00 01 00 80 10 21 03 e0 00 08 } //01 00 
		$a_01_1 = {77 61 62 6a 74 61 6d } //01 00  wabjtam
		$a_01_2 = {62 65 61 72 64 72 6f 70 70 65 72 } //01 00  beardropper
		$a_01_3 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 } //00 00  /bin/busybox
	condition:
		any of ($a_*)
 
}