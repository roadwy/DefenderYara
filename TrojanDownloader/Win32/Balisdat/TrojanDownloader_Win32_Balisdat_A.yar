
rule TrojanDownloader_Win32_Balisdat_A{
	meta:
		description = "TrojanDownloader:Win32/Balisdat.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4e 55 52 5c 4e 4f 49 53 52 45 56 54 4e 45 52 52 55 43 5c 53 57 4f 44 4e 49 57 5c 54 46 4f 53 4f 52 43 49 4d 5c 45 52 41 57 54 46 4f 53 } //01 00  NUR\NOISREVTNERRUC\SWODNIW\TFOSORCIM\ERAWTFOS
		$a_01_1 = {56 56 44 44 46 46 00 } //01 00 
		$a_01_2 = {57 69 6e 73 73 79 73 2e 65 78 65 } //01 00  Winssys.exe
		$a_02_3 = {68 74 74 70 3a 2f 2f 90 02 30 2e 67 69 66 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}