
rule Trojan_BAT_Formbook_AMAP_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AMAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 06 58 06 5d 13 [0-0f] 61 [0-0f] 17 58 06 58 06 5d [0-20] 59 20 00 01 00 00 58 20 00 01 00 00 5d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}