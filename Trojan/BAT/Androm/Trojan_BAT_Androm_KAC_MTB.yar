
rule Trojan_BAT_Androm_KAC_MTB{
	meta:
		description = "Trojan:BAT/Androm.KAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 58 20 00 01 00 00 5d 13 07 02 11 06 8f 16 00 00 01 25 71 ?? 00 00 01 07 11 07 91 61 d2 81 ?? 00 00 01 11 06 17 58 13 06 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}