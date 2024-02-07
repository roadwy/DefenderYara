
rule Trojan_Win32_Delf_gen_B{
	meta:
		description = "Trojan:Win32/Delf.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,22 00 22 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //0a 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 5f 53 68 6f 77 49 45 5f 42 79 6b 6b } //0a 00  Download_ShowIE_Bykk
		$a_01_2 = {42 49 54 53 00 } //01 00 
		$a_01_3 = {53 65 72 76 69 63 65 4d 61 69 6e } //01 00  ServiceMain
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //01 00  DownloadFile
		$a_01_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_01_6 = {52 65 67 69 73 74 65 72 53 65 72 76 69 63 65 43 74 72 6c 48 61 6e 64 6c 65 72 41 } //00 00  RegisterServiceCtrlHandlerA
	condition:
		any of ($a_*)
 
}