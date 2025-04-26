
rule Trojan_Win32_BypassUAC_BN_MTB{
	meta:
		description = "Trojan:Win32/BypassUAC.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 41 78 6c 6e 73 74 53 56 5c 57 69 6e 64 6f 77 73 49 6e 73 74 61 6c 6c 61 74 69 6f 6e 41 73 73 69 73 74 61 6e 74 2e 65 78 65 } //4 C:\ProgramData\AxlnstSV\WindowsInstallationAssistant.exe
		$a_01_1 = {43 00 3a 00 2f 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 2f 00 41 00 78 00 6c 00 6e 00 73 00 74 00 53 00 56 00 2f 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 41 00 73 00 73 00 69 00 73 00 74 00 61 00 6e 00 74 00 2e 00 65 00 78 00 65 00 } //4 C:/ProgramData/AxlnstSV/WindowsInstallationAssistant.exe
		$a_01_2 = {65 6e 68 61 6e 63 65 64 2d 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 6c 6f 64 2f 78 6c 73 72 64 2e 63 70 6c } //2 enhanced-google.com/lod/xlsrd.cpl
		$a_01_3 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 41 78 6c 6e 73 74 53 56 5c 78 6c 73 72 64 2e 63 70 6c } //2 C:\ProgramData\AxlnstSV\xlsrd.cpl
		$a_01_4 = {4c 61 73 74 73 73 74 2e 65 78 65 } //2 Lastsst.exe
		$a_01_5 = {42 00 69 00 6c 00 6c 00 5c 00 42 00 69 00 6c 00 6c 00 2e 00 6c 00 6e 00 6b 00 } //2 Bill\Bill.lnk
		$a_01_6 = {47 4a 64 47 6e 2e 63 70 6c } //1 GJdGn.cpl
		$a_01_7 = {47 65 74 54 65 6d 70 50 61 74 68 57 } //1 GetTempPathW
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=10
 
}