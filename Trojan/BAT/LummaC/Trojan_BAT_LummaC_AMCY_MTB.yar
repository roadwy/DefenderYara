
rule Trojan_BAT_LummaC_AMCY_MTB{
	meta:
		description = "Trojan:BAT/LummaC.AMCY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 0c 09 06 08 91 58 20 00 01 00 00 5d 0d 06 09 91 13 ?? 06 09 06 08 91 9c 06 08 11 06 9c 06 08 91 06 09 91 58 20 00 01 00 00 5d [0-10] 25 47 06 11 ?? 91 61 d2 52 11 ?? 17 58 13 05 11 05 03 3f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}