
rule TrojanSpy_Win32_Bancos_JP{
	meta:
		description = "TrojanSpy:Win32/Bancos.JP,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 6b 65 72 6e 65 6c 33 32 2e 65 78 65 } //01 00  C:\WINDOWS\system32\kernel32.exe
		$a_01_1 = {42 42 56 41 20 42 61 6e 63 6f 20 43 6f 6e 74 69 6e 65 6e 74 61 6c 20 2d 20 57 69 6e 64 6f 77 73 20 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 } //01 00  BBVA Banco Continental - Windows Internet Explorer
		$a_01_2 = {47 70 66 53 4c 71 62 45 48 34 7a 4e 4b 72 6e 70 55 4e 44 71 50 4d 71 70 43 62 6e 68 50 4e 39 6b 50 4d 6d 70 43 59 76 62 55 36 4b } //00 00  GpfSLqbEH4zNKrnpUNDqPMqpCbnhPN9kPMmpCYvbU6K
	condition:
		any of ($a_*)
 
}