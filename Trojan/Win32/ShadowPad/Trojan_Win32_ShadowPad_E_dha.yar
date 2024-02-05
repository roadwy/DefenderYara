
rule Trojan_Win32_ShadowPad_E_dha{
	meta:
		description = "Trojan:Win32/ShadowPad.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8a 14 0f 32 d0 88 11 8b d0 69 c0 90 01 04 c1 ea 10 69 d2 90 00 } //0a 00 
		$a_03_1 = {8b 4c 24 04 55 89 e5 81 ec 00 04 00 00 51 68 90 01 02 00 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}