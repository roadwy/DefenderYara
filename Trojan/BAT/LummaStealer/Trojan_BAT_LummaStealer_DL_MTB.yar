
rule Trojan_BAT_LummaStealer_DL_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 30 11 2d 11 2f 91 58 11 2e 11 2f 91 58 20 00 01 00 00 5d 13 30 11 2d 11 30 91 13 32 11 2d 11 30 11 2d 11 2f 91 9c 11 2d 11 2f 11 32 9c 11 2f 17 58 13 2f 11 2f } //1
		$a_01_1 = {11 2e 11 2b 11 2d 91 58 11 2c 11 2d 91 58 20 00 01 00 00 5d 13 2e 11 2b 11 2e 91 13 30 11 2b 11 2e 11 2b 11 2d 91 9c 11 2b 11 2d 11 30 9c 11 2d 17 58 13 2d 11 2d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}