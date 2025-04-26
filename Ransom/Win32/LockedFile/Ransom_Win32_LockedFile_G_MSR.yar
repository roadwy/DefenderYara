
rule Ransom_Win32_LockedFile_G_MSR{
	meta:
		description = "Ransom:Win32/LockedFile.G!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 13 85 d2 74 1a c7 03 00 00 00 00 8b 4a f8 49 7c 0e f0 ff 4a f8 75 08 8d 42 f4 e8 be cf ff ff 83 c3 04 4e 75 da } //1
		$a_01_1 = {8b 4c 94 1c 85 c9 74 10 03 41 fc a9 00 00 00 c0 75 73 39 cf 75 02 31 ff 4a 75 e5 } //1
		$a_03_2 = {73 6f 66 74 5f 34 5f 35 5f 90 10 02 00 5f 61 64 76 2e 65 78 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}