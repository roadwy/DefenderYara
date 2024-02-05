
rule Trojan_Win32_Chrop_DF_MTB{
	meta:
		description = "Trojan:Win32/Chrop.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 83 ec 08 6a 03 } //03 00 
		$a_81_1 = {53 65 74 53 65 63 75 72 69 74 79 44 65 73 63 72 69 70 74 6f 72 44 61 63 6c } //03 00 
		$a_81_2 = {44 6c 6c 49 6e 73 74 61 6c 6c } //03 00 
		$a_81_3 = {53 6f 66 74 77 61 72 65 20 47 6d 62 48 } //00 00 
	condition:
		any of ($a_*)
 
}