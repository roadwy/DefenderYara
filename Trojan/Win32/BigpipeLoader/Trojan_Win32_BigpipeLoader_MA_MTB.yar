
rule Trojan_Win32_BigpipeLoader_MA_MTB{
	meta:
		description = "Trojan:Win32/BigpipeLoader.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 44 24 10 00 00 00 00 8d 85 c8 f9 ff ff 89 44 24 0c c7 44 24 08 90 01 04 8b 45 f0 89 44 24 04 8b 45 ec 89 04 24 a1 90 01 04 ff d0 83 ec 14 85 c0 74 90 00 } //10
		$a_01_1 = {43 72 79 70 74 44 65 63 72 79 70 74 } //1 CryptDecrypt
		$a_01_2 = {4e 74 51 75 65 72 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 } //1 NtQueryInformationProcess
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}