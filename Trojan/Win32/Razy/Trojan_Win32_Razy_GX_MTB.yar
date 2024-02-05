
rule Trojan_Win32_Razy_GX_MTB{
	meta:
		description = "Trojan:Win32/Razy.GX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {68 d8 85 40 00 5a e8 90 01 04 81 c7 90 01 04 81 c7 90 01 04 31 11 81 c1 90 01 04 b8 90 01 04 29 c0 39 d9 75 d6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}