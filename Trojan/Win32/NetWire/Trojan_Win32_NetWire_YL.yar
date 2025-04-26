
rule Trojan_Win32_NetWire_YL{
	meta:
		description = "Trojan:Win32/NetWire.YL,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 61 6c 6c 20 3a 64 65 6c 65 74 65 53 65 6c 66 26 65 78 69 74 20 2f 62 } //1 call :deleteSelf&exit /b
		$a_01_1 = {44 45 4c 20 2f 73 20 22 25 73 22 20 3e 6e 75 6c 20 32 3e 26 31 } //1 DEL /s "%s" >nul 2>&1
		$a_01_2 = {70 69 6e 67 20 31 39 32 2e 30 2e 32 2e 32 20 2d 6e 20 31 20 2d 77 20 25 64 20 3e 6e 75 6c 20 32 3e 26 31 } //1 ping 192.0.2.2 -n 1 -w %d >nul 2>&1
		$a_01_3 = {3a 64 65 6c 65 74 65 53 65 6c 66 } //1 :deleteSelf
		$a_01_4 = {73 74 61 72 74 20 2f 62 20 22 22 20 63 6d 64 20 2f 63 20 64 65 6c 20 22 25 25 } //1 start /b "" cmd /c del "%%
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}