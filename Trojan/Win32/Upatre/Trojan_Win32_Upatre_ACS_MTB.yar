
rule Trojan_Win32_Upatre_ACS_MTB{
	meta:
		description = "Trojan:Win32/Upatre.ACS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {c1 e0 04 89 01 c3 31 08 c3 33 44 24 04 c2 04 00 81 00 90 01 04 c3 29 08 c3 01 08 c3 90 00 } //0a 00 
		$a_02_1 = {76 0f 8a 94 01 90 01 04 88 14 30 40 3b c7 72 f1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}