
rule Trojan_BAT_Cassiopeia_MBJ_MTB{
	meta:
		description = "Trojan:BAT/Cassiopeia.MBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {73 31 00 00 0a 0c 06 08 28 32 00 00 0a 72 90 01 03 70 6f 33 00 00 0a 6f 34 00 00 0a 6f 35 00 00 0a 06 18 6f 36 00 00 0a 06 6f 37 00 00 0a 13 04 02 0d 11 04 09 16 09 8e b7 90 00 } //5
		$a_01_1 = {41 45 53 5f 44 65 63 72 79 70 74 6f 72 } //1 AES_Decryptor
		$a_01_2 = {47 65 74 54 68 65 52 65 73 6f 75 72 63 65 } //1 GetTheResource
		$a_01_3 = {53 70 6c 69 74 } //1 Split
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}