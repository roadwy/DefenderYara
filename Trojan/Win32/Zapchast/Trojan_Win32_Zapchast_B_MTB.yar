
rule Trojan_Win32_Zapchast_B_MTB{
	meta:
		description = "Trojan:Win32/Zapchast.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 54 24 1b 88 54 24 15 0f be 44 24 15 85 c0 75 10 8b 8c 24 e4 00 00 00 89 8c 24 48 01 00 00 eb 1c 0f be 44 24 15 33 84 24 e4 00 00 00 ba 93 01 00 01 f7 e2 89 84 24 e4 00 00 00 eb a5 } //00 00 
	condition:
		any of ($a_*)
 
}