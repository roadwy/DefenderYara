
rule Trojan_BAT_Zusy_AZU_MTB{
	meta:
		description = "Trojan:BAT/Zusy.AZU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {14 0a 16 0c 16 13 05 2b 0c 00 08 17 58 0c 00 11 05 17 58 13 05 11 05 ?? ?? ?? ?? ?? fe 04 13 06 11 06 2d e5 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}