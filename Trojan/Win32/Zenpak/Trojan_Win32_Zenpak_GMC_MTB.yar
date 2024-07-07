
rule Trojan_Win32_Zenpak_GMC_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 e0 50 8f 05 90 01 04 83 e8 08 e8 90 01 04 42 89 e8 50 8f 05 90 01 04 01 d0 8d 05 90 01 04 01 18 e8 90 01 04 c3 48 48 89 35 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Zenpak_GMC_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.GMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_01_0 = {36 32 2e 31 37 31 2e 31 37 36 2e 32 34 } //1 62.171.176.24
		$a_01_1 = {70 61 79 6c 6f 61 64 2e 64 6c 6c } //1 payload.dll
		$a_01_2 = {30 40 2e 69 64 61 74 61 } //1 0@.idata
		$a_01_3 = {70 61 79 6c 6f 61 64 2e 64 6c 6c 00 6d 61 69 6e 00 70 75 6e 74 00 72 65 63 76 5f 61 6c 6c 00 73 65 72 76 65 72 00 73 65 72 76 65 72 70 00 77 69 6e 73 6f 63 6b 5f 69 6e 69 74 00 77 73 63 6f 6e 6e 65 63 74 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*10) >=13
 
}