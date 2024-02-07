
rule TrojanDownloader_Win32_Banload_BAL{
	meta:
		description = "TrojanDownloader:Win32/Banload.BAL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 32 00 30 00 31 00 34 00 2d 00 32 00 30 00 31 00 35 00 5c 00 5f 00 4e 00 65 00 77 00 73 00 20 00 4c 00 6f 00 61 00 64 00 73 00 20 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 73 00 20 00 65 00 20 00 4d 00 61 00 6e 00 69 00 70 00 75 00 6c 00 61 00 74 00 6f 00 72 00 5c 00 } //01 00  \2014-2015\_News Loads Installs e Manipulator\
		$a_01_1 = {74 4d 65 69 61 48 6f 72 61 } //00 00  tMeiaHora
	condition:
		any of ($a_*)
 
}