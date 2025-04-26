
rule Trojan_Win32_RiseProStealer_AB_MTB{
	meta:
		description = "Trojan:Win32/RiseProStealer.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {fb 9e b5 50 16 bf 4c 42 b4 46 fc 21 0b 8e 6e b8 } //1
		$a_01_1 = {47 65 74 20 6d 79 20 6d 6f 6e 65 79 } //1 Get my money
		$a_01_2 = {50 6f 6c 79 6d 6f 64 58 54 } //1 PolymodXT
		$a_81_3 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 31 30 2e 30 3b 20 57 69 6e 36 34 3b 20 78 36 34 29 20 41 70 70 6c 65 57 65 62 4b 69 74 2f 35 33 37 2e 33 36 20 28 4b 48 54 4d 4c 2c 20 6c 69 6b 65 20 47 65 63 6b 6f 29 20 43 68 72 6f 6d 65 2f 31 31 35 2e 30 2e 30 2e 30 20 53 61 66 61 72 69 2f 35 33 37 2e 33 36 } //1 Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36
		$a_81_4 = {66 61 69 6c 65 64 20 72 65 61 64 70 61 63 6b 65 74 } //1 failed readpacket
		$a_81_5 = {66 61 69 65 6c 64 20 73 65 6e 64 70 61 63 6b 65 74 } //1 faield sendpacket
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}