
rule Trojan_BAT_AsyncRAT_PDJ_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.PDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 00 0a 0b 02 73 14 00 00 0a 0c 08 07 16 73 15 00 00 0a 0d 73 16 00 00 0a 13 04 09 11 04 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 05 } //5
		$a_01_1 = {06 18 6f 10 00 00 0a 06 06 6f 11 00 00 0a 06 6f 12 00 00 0a 6f 13 00 00 0a 0b 02 73 14 00 00 0a 0c 08 07 16 73 15 00 00 0a 0d 73 16 00 00 0a 13 04 09 11 04 6f 17 00 00 0a 11 04 6f 18 00 00 0a 13 05 } //3
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*3) >=8
 
}
rule Trojan_BAT_AsyncRAT_PDJ_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRAT.PDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 06 00 00 "
		
	strings :
		$a_03_0 = {00 00 0a 72 6c fb 01 70 6f ?? 00 00 0a 6f ?? 00 00 0a 06 1f 10 8d 0f 00 00 01 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0b 02 73 ?? 00 00 0a 0c 08 07 16 73 ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 09 11 04 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 05 de 34 } //6
		$a_81_1 = {66 69 64 64 6c 65 72 } //1 fiddler
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_4 = {76 62 6f 78 73 65 72 76 69 63 65 } //1 vboxservice
		$a_81_5 = {76 6d 74 6f 6f 6c 73 64 } //1 vmtoolsd
	condition:
		((#a_03_0  & 1)*6+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=11
 
}