
rule Trojan_BAT_Bobik_CNS_MTB{
	meta:
		description = "Trojan:BAT/Bobik.CNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 00 00 fe 90 01 03 fe 90 01 03 6f 90 01 04 fe 90 01 03 fe 90 01 03 fe 90 01 03 6f 90 01 04 5d 6f 90 01 04 61 d1 6f 90 01 04 26 fe 90 01 03 20 90 01 04 58 fe 90 01 03 fe 90 01 03 fe 90 01 03 6f 90 01 04 3f 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}