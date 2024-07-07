
rule Trojan_BAT_Donut_KAB_MTB{
	meta:
		description = "Trojan:BAT/Donut.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 61 0b 07 20 90 01 04 61 07 20 90 01 04 62 0b 59 0a 07 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}