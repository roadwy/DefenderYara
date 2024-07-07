
rule Trojan_Win32_Trickbot_AVI_MSR{
	meta:
		description = "Trojan:Win32/Trickbot.AVI!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {63 68 71 69 54 72 5a 71 69 6f 51 39 57 66 70 4a 43 45 5a 6b 5a 78 42 46 6a 62 41 6e 72 65 7a 73 45 58 67 5a 46 55 57 42 } //1 chqiTrZqioQ9WfpJCEZkZxBFjbAnrezsEXgZFUWB
		$a_81_1 = {73 64 6b 64 69 66 66 5c 57 69 6e 33 32 5c 52 65 6c 65 61 73 65 5c 73 64 6b 64 69 66 66 2e 70 64 62 } //1 sdkdiff\Win32\Release\sdkdiff.pdb
		$a_81_2 = {73 64 6b 64 69 66 66 2e 65 78 65 } //1 sdkdiff.exe
		$a_81_3 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_81_4 = {43 4c 53 49 44 5c 7b 41 44 42 38 38 30 41 36 2d 44 38 46 46 2d 31 31 43 46 2d 39 33 37 37 2d 30 30 41 41 30 30 33 42 37 41 31 31 7d 5c 49 6e 70 72 6f 63 53 65 72 76 65 72 33 32 } //1 CLSID\{ADB880A6-D8FF-11CF-9377-00AA003B7A11}\InprocServer32
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}