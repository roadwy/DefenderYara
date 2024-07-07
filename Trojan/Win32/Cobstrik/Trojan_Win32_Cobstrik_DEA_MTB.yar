
rule Trojan_Win32_Cobstrik_DEA_MTB{
	meta:
		description = "Trojan:Win32/Cobstrik.DEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 23 19 00 00 b8 23 19 00 00 b8 23 19 00 00 b8 23 19 00 00 b8 23 19 00 00 a1 90 01 04 a3 90 01 04 eb 00 31 0d 90 01 04 c7 05 90 01 04 00 00 00 00 a1 90 01 04 01 05 90 01 04 8b ff a1 90 01 04 8b 0d 90 01 04 89 08 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}