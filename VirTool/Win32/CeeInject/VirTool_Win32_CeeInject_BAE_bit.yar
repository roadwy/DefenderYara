
rule VirTool_Win32_CeeInject_BAE_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BAE!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 72 6f 74 65 63 74 2e 65 78 65 } //1 protect.exe
		$a_01_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 63 42 4c 4b 2e 64 6c 6c } //1 C:\Windows\System32\cBLK.dll
		$a_01_2 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 31 32 33 34 64 66 2e 64 6c 6c } //1 C:\Program Files\1234df.dll
		$a_01_3 = {46 45 41 54 55 52 45 5f 43 72 6f 73 73 5f 44 6f 6d 61 69 6e 5f 52 65 64 69 72 65 63 74 5f 4d 69 74 69 67 61 74 69 6f 6e } //1 FEATURE_Cross_Domain_Redirect_Mitigation
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}