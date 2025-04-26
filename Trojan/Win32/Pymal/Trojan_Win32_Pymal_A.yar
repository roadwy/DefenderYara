
rule Trojan_Win32_Pymal_A{
	meta:
		description = "Trojan:Win32/Pymal.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 22 3d 22 45 78 70 6c 6f 72 65 72 2e 65 78 65 2c 57 69 6e 64 6f 77 73 2e 65 78 65 22 } //1 Shell"="Explorer.exe,Windows.exe"
		$a_01_1 = {77 68 61 74 69 73 6d 79 69 70 2e 63 6f 6d 2f 61 75 74 6f 6d 61 74 69 6f 6e } //1 whatismyip.com/automation
		$a_01_2 = {4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 50 72 6f 66 69 6c 65 73 } //1 Mozilla\Firefox\Profiles
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}