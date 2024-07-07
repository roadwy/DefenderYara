
rule Trojan_Win32_Patched_V{
	meta:
		description = "Trojan:Win32/Patched.V,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 e8 34 89 85 90 01 04 61 ff 34 24 60 e8 00 00 00 00 5d 81 ed 90 01 04 8b 85 90 01 04 89 44 24 24 61 5d 83 7c 24 0c 01 75 26 60 e8 00 00 00 00 5d 81 ed 90 01 04 8d b5 90 01 04 56 8b bd 90 01 04 ff d7 90 00 } //1
		$a_03_1 = {55 60 e8 00 00 00 00 90 90 90 90 8b f6 5d 81 ed 90 01 04 60 e8 00 00 00 00 58 25 00 f0 ff ff 90 00 } //1
		$a_00_2 = {a4 cf 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 6d 73 63 74 66 69 6d 65 2e 69 65 6d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}