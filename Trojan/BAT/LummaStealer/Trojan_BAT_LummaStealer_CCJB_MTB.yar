
rule Trojan_BAT_LummaStealer_CCJB_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.CCJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 06 03 04 6f 17 00 00 0a 0b 02 07 28 05 00 00 06 0c de 14 07 2c 06 07 6f 18 00 00 0a dc 06 2c 06 06 6f 18 00 00 0a dc 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_LummaStealer_CCJB_MTB_2{
	meta:
		description = "Trojan:BAT/LummaStealer.CCJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 07 06 07 93 20 98 00 00 00 61 02 61 d1 9d 07 17 59 25 0b 16 2f e9 } //1
		$a_01_1 = {11 06 11 07 11 05 11 07 6f d9 00 00 0a 20 67 0f 00 00 61 d1 9d 1f 09 13 09 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}