
rule Trojan_BAT_Bladabindi_BU_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.BU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {20 00 04 00 00 8d 90 01 01 00 00 01 13 0d 2b 0f 00 11 0b 11 0d 16 11 0c 6f 90 01 01 00 00 0a 00 00 11 0a 11 0d 16 11 0d 8e 69 6f 90 01 01 00 00 0a 25 13 0c 16 fe 02 13 0e 11 0e 2d d7 90 00 } //2
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {47 65 74 42 79 74 65 73 } //1 GetBytes
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}