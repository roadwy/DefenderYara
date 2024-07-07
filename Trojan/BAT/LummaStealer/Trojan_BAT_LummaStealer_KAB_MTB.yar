
rule Trojan_BAT_LummaStealer_KAB_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {05 11 0a 8f 90 01 01 00 00 01 25 71 90 01 01 00 00 01 06 11 0e 91 61 d2 90 00 } //1
		$a_01_1 = {11 0f 11 10 11 10 08 58 9e 11 10 17 58 13 10 11 10 11 0f 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}