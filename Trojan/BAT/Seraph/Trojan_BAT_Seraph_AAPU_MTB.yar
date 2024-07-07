
rule Trojan_BAT_Seraph_AAPU_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAPU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 02 28 90 01 01 00 00 06 75 90 01 01 00 00 1b 73 90 01 01 00 00 0a 0d 09 07 16 73 90 01 01 00 00 0a 13 04 11 04 08 6f 90 01 01 00 00 0a 08 13 05 dd 90 01 01 00 00 00 11 04 39 90 01 01 00 00 00 11 04 6f 90 01 01 00 00 0a dc 90 00 } //3
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}