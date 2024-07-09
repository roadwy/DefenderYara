
rule Trojan_BAT_RedLineStealer_KAI_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.KAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {05 11 0d 8f ?? 00 00 01 25 71 ?? 00 00 01 07 11 11 91 61 d2 } //1
		$a_01_1 = {11 12 11 13 11 13 09 58 9e 11 13 17 58 13 13 11 13 11 12 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}