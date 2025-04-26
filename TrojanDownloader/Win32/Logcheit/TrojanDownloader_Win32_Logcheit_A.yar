
rule TrojanDownloader_Win32_Logcheit_A{
	meta:
		description = "TrojanDownloader:Win32/Logcheit.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4c 6f 67 69 6e 20 43 68 65 61 74 } //1 Login Cheat
		$a_01_1 = {4d 00 75 00 6c 00 61 00 69 00 20 00 49 00 6e 00 6a 00 65 00 63 00 74 00 } //1 Mulai Inject
		$a_01_2 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 50 00 44 00 46 00 2e 00 2e 00 } //1 \Windows\PDF..
		$a_01_3 = {44 00 6c 00 6c 00 20 00 73 00 75 00 63 00 63 00 65 00 73 00 66 00 75 00 6c 00 6c 00 79 00 20 00 69 00 6e 00 6a 00 65 00 63 00 74 00 65 00 64 00 21 00 } //1 Dll succesfully injected!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}