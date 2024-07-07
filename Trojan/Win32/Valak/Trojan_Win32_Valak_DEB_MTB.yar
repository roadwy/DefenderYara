
rule Trojan_Win32_Valak_DEB_MTB{
	meta:
		description = "Trojan:Win32/Valak.DEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 54 24 18 81 c1 90 01 04 8b 44 24 14 05 90 01 04 89 44 24 14 89 02 8b 54 24 10 0f b7 d2 c1 e2 02 2b d6 a3 90 01 04 03 d1 8b 4c 24 10 0f b7 c1 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}