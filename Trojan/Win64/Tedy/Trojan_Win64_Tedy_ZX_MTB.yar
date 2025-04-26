
rule Trojan_Win64_Tedy_ZX_MTB{
	meta:
		description = "Trojan:Win64/Tedy.ZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {32 54 03 10 48 c1 f9 10 31 f2 31 ca 48 89 f1 48 c1 f9 18 31 ca 48 8d 4e 01 88 54 03 10 } //1
		$a_01_1 = {73 74 61 74 69 63 2f 6c 6f 61 64 65 72 5f 63 6c 69 65 6e 74 5f 6e 6f 5f 6c 69 74 65 72 61 6c 73 5f 63 6f 6d 70 72 65 73 73 69 6f 6e 2e 62 69 6e } //1 static/loader_client_no_literals_compression.bin
		$a_01_2 = {64 58 4e 6c 63 6a 70 52 64 32 56 79 64 48 6b 78 4d 6a 4d 68 } //1 dXNlcjpRd2VydHkxMjMh
		$a_01_3 = {75 70 64 61 74 65 72 2e 65 78 65 } //1 updater.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}