
rule Trojan_BAT_BypassUAC_NG_MTB{
	meta:
		description = "Trojan:BAT/BypassUAC.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_81_0 = {65 31 65 64 65 32 36 63 2d 36 36 34 35 2d 34 39 63 63 2d 39 63 31 65 2d 35 32 64 31 33 32 66 37 61 35 37 31 } //2 e1ede26c-6645-49cc-9c1e-52d132f7a571
		$a_81_1 = {53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 5c 6d 73 2d 73 65 74 74 69 6e 67 73 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 Software\Classes\ms-settings\shell\open\command
		$a_81_2 = {53 79 73 74 65 6d 33 32 5c 66 6f 64 68 65 6c 70 65 72 2e 65 78 65 } //1 System32\fodhelper.exe
		$a_81_3 = {56 4d 20 44 45 54 45 43 54 45 44 } //1 VM DETECTED
		$a_81_4 = {53 61 6e 64 62 6f 78 20 44 45 54 45 43 54 45 44 } //1 Sandbox DETECTED
		$a_81_5 = {44 4f 57 4e 4c 4f 41 44 46 49 4c 45 } //1 DOWNLOADFILE
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=7
 
}