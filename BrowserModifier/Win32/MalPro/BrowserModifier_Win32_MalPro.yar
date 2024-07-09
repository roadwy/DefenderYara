
rule BrowserModifier_Win32_MalPro{
	meta:
		description = "BrowserModifier:Win32/MalPro,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 61 00 6c 00 77 00 61 00 72 00 65 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 33 00 36 00 30 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 64 00 } //1 Software\MalwareProtection360Installed
		$a_01_1 = {4d 61 6c 77 61 72 65 50 72 6f 74 65 63 74 69 6f 6e 33 36 30 2e 50 72 6f 70 65 72 74 69 65 73 } //1 MalwareProtection360.Properties
		$a_02_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 64 00 31 00 68 00 78 00 74 00 6c 00 39 00 7a 00 6e 00 71 00 77 00 65 00 6a 00 6a 00 2e 00 63 00 6c 00 6f 00 75 00 64 00 [0-0f] 2e 00 6e 00 65 00 74 00 2f 00 61 00 70 00 69 00 2f 00 69 00 6d 00 70 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}