
rule TrojanSpy_Win32_Batund_A{
	meta:
		description = "TrojanSpy:Win32/Batund.A,SIGNATURE_TYPE_PEHSTR,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 6f 6b 2e 70 68 70 3f 61 3d 25 75 73 65 72 6e 61 6d 65 25 26 62 3d 25 63 6f 6d 70 75 74 65 72 6e 61 6d 65 25 26 63 3d 25 6d 61 63 25 22 29 26 26 66 73 75 74 69 6c 20 66 69 6c 65 20 63 72 65 61 74 65 6e 65 77 20 22 25 74 65 6d 70 25 5c 74 68 75 6e 62 2e 64 62 } //5 /ok.php?a=%username%&b=%computername%&c=%mac%")&&fsutil file createnew "%temp%\thunb.db
		$a_01_1 = {5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 22 20 2f 76 20 45 6e 61 62 6c 65 4c 55 41 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 30 } //1 \Policies\System" /v EnableLUA /t REG_DWORD /d 0
		$a_01_2 = {5c 44 6f 6d 61 69 6e 73 5c 63 6f 6d 2e 62 72 5c 2a 2e 62 72 61 64 65 73 63 6f 22 20 2f 76 20 22 68 74 74 70 22 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 22 30 78 30 30 30 30 30 30 30 32 22 20 2f 66 } //1 \Domains\com.br\*.bradesco" /v "http" /t REG_DWORD /d "0x00000002" /f
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}