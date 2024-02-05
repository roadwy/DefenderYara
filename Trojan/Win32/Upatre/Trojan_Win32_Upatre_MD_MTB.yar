
rule Trojan_Win32_Upatre_MD_MTB{
	meta:
		description = "Trojan:Win32/Upatre.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 c4 10 56 68 80 00 00 00 6a 03 56 6a 01 68 00 00 00 80 ff 75 f0 ff 15 } //01 00 
		$a_01_1 = {56 8d 4d e8 51 ff 75 ec 50 ff 75 f8 ff 15 } //01 00 
		$a_01_2 = {8d 44 43 04 50 ff 75 e0 ff 75 f4 ff 15 } //01 00 
		$a_01_3 = {3a 00 5c 00 54 00 45 00 4d 00 50 00 5c 00 68 00 63 00 62 00 6e 00 61 00 66 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}