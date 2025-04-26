
rule Trojan_Win32_LummaC_AMAJ_MTB{
	meta:
		description = "Trojan:Win32/LummaC.AMAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 8b 45 ?? 31 18 6a 00 e8 [0-14] 83 45 ec 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}