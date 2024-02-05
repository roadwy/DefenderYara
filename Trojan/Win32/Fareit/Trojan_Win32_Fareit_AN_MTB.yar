
rule Trojan_Win32_Fareit_AN_MTB{
	meta:
		description = "Trojan:Win32/Fareit.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 0f 6e c6 90 02 10 66 0f 6e c9 90 02 10 66 0f 57 c8 90 02 10 66 0f 7e c9 90 02 10 39 c1 75 90 01 01 90 02 20 b8 90 01 04 90 02 15 05 90 02 15 8b 00 90 02 15 68 90 01 04 90 02 15 5b 90 02 15 81 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}