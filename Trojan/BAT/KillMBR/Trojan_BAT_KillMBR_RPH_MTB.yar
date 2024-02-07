
rule Trojan_BAT_KillMBR_RPH_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.RPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {20 00 02 00 00 8d 14 00 00 01 0a 72 01 00 00 70 20 00 00 00 10 19 7e 12 00 00 0a 19 16 7e 12 00 00 0a 28 02 00 00 06 } //01 00 
		$a_01_1 = {5c 00 5c 00 2e 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 30 00 } //01 00  \\.\PhysicalDrive0
		$a_01_2 = {4d 62 72 4f 76 65 72 77 72 69 74 65 72 } //01 00  MbrOverwriter
		$a_01_3 = {4d 62 72 53 69 7a 65 } //01 00  MbrSize
		$a_01_4 = {57 72 69 74 65 4c 69 6e 65 } //01 00  WriteLine
		$a_01_5 = {6c 70 42 75 66 66 65 72 } //00 00  lpBuffer
	condition:
		any of ($a_*)
 
}