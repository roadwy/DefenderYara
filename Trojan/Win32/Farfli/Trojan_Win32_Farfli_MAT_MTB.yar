
rule Trojan_Win32_Farfli_MAT_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 "
		
	strings :
		$a_01_0 = {e8 47 3c ad ff 74 24 02 eb 24 88 2b 42 fd ff 74 24 04 8d 64 24 08 66 50 ff 74 24 03 8d 64 24 02 89 4c 24 20 eb 14 cc 5f a6 d1 10 91 cb b3 79 de } //10
		$a_01_1 = {2e 73 65 64 61 74 61 } //5 .sedata
		$a_01_2 = {4e 74 51 75 65 72 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 54 68 72 65 61 64 } //1 NtQueryInformationThread
		$a_01_3 = {49 73 57 6f 77 36 34 50 72 6f 63 65 73 73 } //1 IsWow64Process
		$a_01_4 = {53 45 47 65 74 4c 69 63 65 6e 73 65 55 73 65 72 49 6e 66 6f 57 } //1 SEGetLicenseUserInfoW
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=18
 
}