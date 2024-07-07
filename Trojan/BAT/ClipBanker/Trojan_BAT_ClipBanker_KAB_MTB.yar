
rule Trojan_BAT_ClipBanker_KAB_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 00 00 fe 09 00 00 fe 0c 01 00 6f 90 01 01 00 00 0a 20 90 01 04 61 d1 fe 0e 02 00 fe 0d 02 00 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a fe 0e 00 00 fe 0c 01 00 20 90 01 01 00 00 00 58 fe 0e 01 00 fe 0c 01 00 fe 09 00 00 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}