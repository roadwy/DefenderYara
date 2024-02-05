
rule Trojan_Win32_Qbot_DG_MTB{
	meta:
		description = "Trojan:Win32/Qbot.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {6b 39 70 66 6c 2e 64 6c 6c } //01 00 
		$a_81_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00 
		$a_81_2 = {4d 69 66 44 74 7a 61 4d 68 67 47 } //01 00 
		$a_81_3 = {5a 48 78 62 45 54 6f 70 75 4f 49 } //01 00 
		$a_81_4 = {6a 4b 75 45 6b 68 62 4d 6b 4d 68 59 4b 47 } //01 00 
		$a_81_5 = {67 55 6d 61 6d 58 50 } //01 00 
		$a_81_6 = {45 71 75 61 6c 52 67 6e } //00 00 
	condition:
		any of ($a_*)
 
}