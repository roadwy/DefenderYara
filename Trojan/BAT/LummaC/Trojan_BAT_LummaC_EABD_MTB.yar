
rule Trojan_BAT_LummaC_EABD_MTB{
	meta:
		description = "Trojan:BAT/LummaC.EABD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 0e 29 00 20 81 4a 85 0b 20 04 c0 3e 0d 58 20 6b 2f b0 4a 61 fe 0e 2a 00 fe 0c 26 00 fe 0c 26 00 20 05 00 00 00 62 61 fe 0e 26 00 fe 0c 26 00 fe 0c 28 00 58 fe 0e 26 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}