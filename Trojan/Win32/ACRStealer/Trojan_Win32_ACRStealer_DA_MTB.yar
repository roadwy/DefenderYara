
rule Trojan_Win32_ACRStealer_DA_MTB{
	meta:
		description = "Trojan:Win32/ACRStealer.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {75 73 65 72 5f 70 72 65 66 28 22 65 78 74 65 6e 73 69 6f 6e 73 2e 77 65 62 65 78 74 65 6e 73 69 6f 6e 73 2e 75 75 69 64 73 } //user_pref("extensions.webextensions.uuids  1
		$a_80_1 = {3c 64 69 73 63 61 72 64 65 64 3e } //<discarded>  1
		$a_80_2 = {73 74 65 61 6d 63 6f 6d 6d 75 6e 69 74 79 2e 63 6f 6d } //steamcommunity.com  1
		$a_80_3 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //CreateToolhelp32Snapshot  1
		$a_80_4 = {52 6d 52 65 67 69 73 74 65 72 52 65 73 6f 75 72 63 65 73 } //RmRegisterResources  1
		$a_80_5 = {49 6e 74 65 72 6e 65 74 57 72 69 74 65 46 69 6c 65 } //InternetWriteFile  1
		$a_80_6 = {52 73 74 72 74 4d 67 72 2e 44 4c 4c } //RstrtMgr.DLL  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}