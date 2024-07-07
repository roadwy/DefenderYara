
rule Trojan_Win32_CryptInject_AS_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 00 5c 00 2e 00 5c 00 61 00 76 00 67 00 53 00 50 00 5f 00 4f 00 70 00 65 00 6e 00 } //1 \\.\avgSP_Open
		$a_02_1 = {31 ca 59 8a 0c 10 5a 84 c9 75 12 8b 0d 90 01 04 8a 1d 90 01 04 03 c8 03 cf 30 19 39 15 90 01 04 76 03 40 eb 01 cb 90 00 } //1
		$a_00_2 = {03 d9 03 c8 46 8a 1c 03 88 1c 39 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule Trojan_Win32_CryptInject_AS_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 45 e4 40 89 45 90 01 01 8b 45 90 01 01 3b 05 90 01 04 73 90 01 01 a1 90 01 04 89 45 90 01 01 b8 90 01 04 01 45 90 01 01 a1 90 01 04 03 45 90 01 01 8b 4d 90 01 01 03 4d 90 01 01 8a 09 88 08 eb 90 00 } //1
		$a_00_1 = {69 c9 fd 43 03 00 81 c1 c3 9e 26 00 8b c1 c1 e8 10 30 04 1e 46 3b f7 7c e7 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule Trojan_Win32_CryptInject_AS_MTB_3{
	meta:
		description = "Trojan:Win32/CryptInject.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {30 04 13 43 3b df 7c 90 0a 4f 00 81 ff 90 01 02 00 00 75 13 56 ff 15 90 01 03 00 8b 0d 90 01 03 00 8b 95 90 01 02 ff ff 69 c9 90 01 03 00 81 c1 90 01 03 00 8b c1 89 0d 90 01 03 00 c1 e8 10 30 04 13 43 3b df 7c 90 00 } //1
		$a_02_1 = {30 04 1f 47 3b fe 7c 90 0a 4f 00 81 fe 90 01 02 00 00 75 0e 6a 00 ff 15 90 01 03 00 8b 0d 90 01 03 00 69 c9 90 01 03 00 81 c1 90 01 03 00 8b c1 89 0d 90 01 03 00 c1 e8 10 30 04 1f 47 3b fe 7c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}