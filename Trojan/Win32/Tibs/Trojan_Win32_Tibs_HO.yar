
rule Trojan_Win32_Tibs_HO{
	meta:
		description = "Trojan:Win32/Tibs.HO,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5a 58 01 df 90 17 03 14 06 03 (83 c7 14 83 ef 19|83 ef ?? 81 ef ?? ?? ?? ?? 83) c7 0a 83 ef 0f 83 ef 05 e2 90 14 ab 50 52 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}