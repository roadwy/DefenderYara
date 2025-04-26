
rule Trojan_Win32_Relinestealer_UH_MTB{
	meta:
		description = "Trojan:Win32/Relinestealer.UH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 d8 31 d2 f7 75 ?? 8b 45 ?? 0f be 04 10 69 c0 ?? ?? ?? ?? 30 04 1e 43 } //10
		$a_03_1 = {0f be d9 77 ?? 83 c9 ?? 0f be d9 31 fb 69 fb ?? ?? ?? ?? eb } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}