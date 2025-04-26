
rule Trojan_Win32_ShadowPad_E_dha{
	meta:
		description = "Trojan:Win32/ShadowPad.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 14 0f 32 d0 88 11 8b d0 69 c0 ?? ?? ?? ?? c1 ea 10 69 d2 } //10
		$a_03_1 = {8b 4c 24 04 55 89 e5 81 ec 00 04 00 00 51 68 ?? ?? 00 00 e8 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}