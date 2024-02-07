
rule TrojanDownloader_Win32_Banload_XP{
	meta:
		description = "TrojanDownloader:Win32/Banload.XP,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {3a 5c 77 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 90 02 05 2e 74 78 74 90 00 } //01 00 
		$a_00_1 = {49 6e 74 65 6c 69 67 65 6e 63 69 61 20 41 72 74 69 66 69 63 69 61 6c 20 41 43 54 } //01 00  Inteligencia Artificial ACT
		$a_00_2 = {3a 2a 3a 45 6e 61 62 6c 65 64 3a 4d 69 63 72 6f 73 6f 66 74 20 57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 20 50 6c 61 74 66 6f 72 6d } //01 00  :*:Enabled:Microsoft Windows Update Platform
		$a_00_3 = {69 6e 74 65 72 6e 65 74 62 61 6e 6b 69 6e 67 63 61 69 78 61 6d 6f 7a 69 6c 6c 61 66 69 72 65 66 6f 78 } //01 00  internetbankingcaixamozillafirefox
		$a_00_4 = {77 77 77 2e 67 72 75 70 6f 62 63 69 2e 63 6f 6d 2e 62 72 2f 73 69 73 74 65 6d 61 2f } //01 00  www.grupobci.com.br/sistema/
		$a_00_5 = {42 61 6e 63 6f 20 53 61 6e 74 61 6e 64 65 72 20 42 72 61 73 69 6c } //00 00  Banco Santander Brasil
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Banload_XP_2{
	meta:
		description = "TrojanDownloader:Win32/Banload.XP,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 74 65 6d 70 2f 73 73 2e 63 6f 6d } //01 00  /temp/ss.com
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
		$a_01_2 = {58 50 50 52 4f 42 54 32 30 30 39 } //00 00  XPPROBT2009
	condition:
		any of ($a_*)
 
}