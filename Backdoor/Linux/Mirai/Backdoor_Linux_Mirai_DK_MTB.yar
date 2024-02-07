
rule Backdoor_Linux_Mirai_DK_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.DK!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 62 6f 61 74 } //01 00  /bin/busybox boat
		$a_01_1 = {73 63 61 6e 6e 65 72 5f 6b 69 6c 6c } //01 00  scanner_kill
		$a_01_2 = {72 69 70 70 65 72 5f 61 74 74 61 63 6b } //00 00  ripper_attack
	condition:
		any of ($a_*)
 
}