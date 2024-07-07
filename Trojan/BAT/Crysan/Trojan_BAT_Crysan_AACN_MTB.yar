
rule Trojan_BAT_Crysan_AACN_MTB{
	meta:
		description = "Trojan:BAT/Crysan.AACN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 09 00 00 0a 03 50 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0b 73 90 01 01 00 00 0a 0c 08 07 6f 90 01 01 00 00 0a 08 18 6f 90 01 01 00 00 0a 08 6f 90 01 01 00 00 0a 02 50 16 02 50 8e 69 6f 90 01 01 00 00 0a 2a 90 00 } //3
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}