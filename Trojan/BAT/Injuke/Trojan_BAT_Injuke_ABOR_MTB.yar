
rule Trojan_BAT_Injuke_ABOR_MTB{
	meta:
		description = "Trojan:BAT/Injuke.ABOR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 07 17 73 90 01 03 0a 0d 00 09 03 16 03 8e 69 6f 90 01 03 0a 00 09 6f 90 01 03 0a 00 08 6f 90 01 03 0a 13 04 de 21 09 2c 07 09 6f 90 01 03 0a 00 dc 90 0a 3f 00 06 6f 90 01 03 0a 0b 73 90 00 } //6
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_2 = {46 6c 75 73 68 46 69 6e 61 6c 42 6c 6f 63 6b } //1 FlushFinalBlock
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*6+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=10
 
}