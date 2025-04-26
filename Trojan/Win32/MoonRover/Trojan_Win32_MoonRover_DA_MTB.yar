
rule Trojan_Win32_MoonRover_DA_MTB{
	meta:
		description = "Trojan:Win32/MoonRover.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 20 00 56 00 6f 00 6c 00 75 00 6d 00 65 00 20 00 49 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 5c 00 2a 00 2e 00 2a 00 } //1 C:\System Volume Information\*.*
		$a_01_1 = {43 00 3a 00 5c 00 61 00 61 00 61 00 5f 00 54 00 6f 00 75 00 63 00 68 00 4d 00 65 00 4e 00 6f 00 74 00 5f 00 5c 00 2a 00 2e 00 2a 00 } //1 C:\aaa_TouchMeNot_\*.*
		$a_01_2 = {57 69 6e 53 6f 63 6b 20 32 2e 30 } //1 WinSock 2.0
		$a_01_3 = {4d 50 47 6f 6f 64 53 74 61 74 75 73 } //1 MPGoodStatus
		$a_01_4 = {47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 73 } //1 GetLogicalDrives
		$a_01_5 = {47 65 74 44 69 73 6b 46 72 65 65 53 70 61 63 65 57 } //1 GetDiskFreeSpaceW
		$a_01_6 = {4f 20 4d 61 6d 6d 61 20 4d 69 61 2e 2e 2e } //1 O Mamma Mia...
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}