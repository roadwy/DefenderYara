
rule Trojan_BAT_Fsysna_GBX_MTB{
	meta:
		description = "Trojan:BAT/Fsysna.GBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 8d 39 00 00 01 13 04 7e a5 00 00 04 02 1a 58 11 04 16 08 28 90 01 03 0a 28 90 01 03 0a 11 04 16 11 04 8e 69 6f 90 01 03 0a 13 05 7e 8f 00 00 04 11 05 6f 90 01 03 0a 7e 90 00 } //10
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}