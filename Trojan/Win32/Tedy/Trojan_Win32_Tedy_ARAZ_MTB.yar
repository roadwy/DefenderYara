
rule Trojan_Win32_Tedy_ARAZ_MTB{
	meta:
		description = "Trojan:Win32/Tedy.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 63 6d 73 74 70 2e 65 78 65 20 2f 61 75 20 25 54 45 4d 50 25 5c 63 6f 72 70 76 70 6e 2e 69 6e 66 } //2 cmd.exe /c C:\Windows\System32\cmstp.exe /au %TEMP%\corpvpn.inf
		$a_01_1 = {61 68 75 66 67 69 75 61 67 75 69 6a 61 73 62 69 75 61 69 62 75 68 61 69 75 68 62 } //2 ahufgiuaguijasbiuaibuhaiuhb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}