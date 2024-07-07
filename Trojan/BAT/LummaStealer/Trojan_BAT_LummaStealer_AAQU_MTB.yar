
rule Trojan_BAT_LummaStealer_AAQU_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.AAQU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 0b 07 28 90 01 01 00 00 06 0d 16 20 ae 0b 0c 00 d8 7e 90 01 01 02 00 04 7b 90 01 01 02 00 04 2d 10 26 72 01 00 00 70 18 28 90 01 02 00 0a 2b 02 11 09 90 00 } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}