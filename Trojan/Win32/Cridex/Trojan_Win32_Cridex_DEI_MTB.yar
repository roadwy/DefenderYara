
rule Trojan_Win32_Cridex_DEI_MTB{
	meta:
		description = "Trojan:Win32/Cridex.DEI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 e8 55 2b 05 90 01 04 a3 90 01 04 8b 0d 90 1b 01 6b c9 36 8b 15 90 1b 01 2b d1 89 15 90 1b 00 8b 45 f4 6b c0 06 2b 05 90 1b 01 a3 90 1b 00 0f b7 0d 90 01 04 81 e9 90 01 04 2b 0d 90 01 04 33 d2 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}