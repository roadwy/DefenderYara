
rule Trojan_Win32_Stelega_RM_MTB{
	meta:
		description = "Trojan:Win32/Stelega.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_03_0 = {81 c7 38 33 fa 44 e8 90 01 04 89 d7 81 c7 15 ac e1 5d 89 ff 31 06 09 d7 81 c6 01 00 00 00 01 fa 39 ce 75 90 00 } //1
		$a_03_1 = {81 ef 76 eb 7c bf 48 e8 90 01 04 81 c0 dd 1f dc 4c 31 16 68 90 01 04 58 48 46 01 ff 81 ef 90 00 } //1
		$a_03_2 = {81 c0 c1 78 8b ee e8 90 01 04 09 c1 31 16 21 c0 46 51 58 29 c1 90 00 } //1
		$a_03_3 = {83 c4 04 e8 90 01 04 01 c9 09 c9 21 c9 31 16 bb 3f df eb 74 01 cb 4b 46 81 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=1
 
}
rule Trojan_Win32_Stelega_RM_MTB_2{
	meta:
		description = "Trojan:Win32/Stelega.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 06 00 00 "
		
	strings :
		$a_01_0 = {31 6f 69 76 76 69 6f 76 69 64 77 6f 70 6f 70 69 6e 2e 69 6e 66 6f } //10 1oivviovidwopopin.info
		$a_01_1 = {43 3a 5c 57 6f 72 6b 5c 66 69 6e 64 65 72 32 5c 70 72 65 70 61 72 65 72 5c 52 65 6c 65 61 73 65 5c 70 72 65 70 61 72 65 72 2e 70 64 62 } //10 C:\Work\finder2\preparer\Release\preparer.pdb
		$a_01_2 = {4d 61 6c 66 6f 72 6d 65 64 20 65 6e 63 6f 64 69 6e 67 20 66 6f 75 6e 64 } //1 Malformed encoding found
		$a_01_3 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 } //1 \Google\Chrome\User Data
		$a_01_4 = {5c 44 65 66 61 75 6c 74 5c 48 69 73 74 6f 72 79 } //1 \Default\History
		$a_01_5 = {43 6f 6f 6b 69 65 73 } //1 Cookies
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=24
 
}