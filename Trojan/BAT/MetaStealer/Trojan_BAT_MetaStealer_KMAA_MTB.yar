
rule Trojan_BAT_MetaStealer_KMAA_MTB{
	meta:
		description = "Trojan:BAT/MetaStealer.KMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 01 91 11 05 11 02 91 58 20 00 01 00 00 5d } //2
		$a_03_1 = {03 11 17 8f 90 01 01 00 00 01 25 71 90 01 01 00 00 01 11 05 11 13 6f 90 01 01 00 00 0a a5 90 01 01 00 00 01 61 d2 90 00 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}