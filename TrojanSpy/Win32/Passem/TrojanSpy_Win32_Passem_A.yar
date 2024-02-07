
rule TrojanSpy_Win32_Passem_A{
	meta:
		description = "TrojanSpy:Win32/Passem.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {4d 61 63 3a 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 } //03 00  Mac:%02X-%02X-%02X-%02X-%02X-%02X
		$a_01_1 = {63 6d 64 2e 65 78 65 20 2f 63 20 25 73 } //04 00  cmd.exe /c %s
		$a_01_2 = {5c 6d 73 73 61 70 33 32 2e 64 6c 6c } //00 00  \mssap32.dll
		$a_00_3 = {5d 04 00 00 ad fa } //02 80 
	condition:
		any of ($a_*)
 
}