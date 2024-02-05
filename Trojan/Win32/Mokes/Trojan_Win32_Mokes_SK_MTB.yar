
rule Trojan_Win32_Mokes_SK_MTB{
	meta:
		description = "Trojan:Win32/Mokes.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {6d 5f 74 65 6d 70 62 72 75 73 68 } //01 00 
		$a_81_1 = {6d 5f 64 72 61 77 4e 75 6d 50 65 6e } //01 00 
		$a_81_2 = {41 66 78 57 6e 64 39 30 73 64 } //01 00 
		$a_81_3 = {41 66 78 4f 6c 64 57 6e 64 50 72 6f 63 34 32 33 } //00 00 
	condition:
		any of ($a_*)
 
}