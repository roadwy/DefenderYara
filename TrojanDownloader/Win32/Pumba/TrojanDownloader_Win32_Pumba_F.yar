
rule TrojanDownloader_Win32_Pumba_F{
	meta:
		description = "TrojanDownloader:Win32/Pumba.F,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 68 65 63 6b 69 70 2e 64 79 6e 64 6e 73 2e 6f 72 67 2f } //01 00  checkip.dyndns.org/
		$a_01_1 = {69 70 2d 61 70 69 2e 63 6f 6d 2f 6a 73 6f 6e 2f } //01 00  ip-api.com/json/
		$a_01_2 = {5c 44 50 52 30 30 39 2e 65 78 65 } //01 00  \DPR009.exe
		$a_01_3 = {67 62 70 73 76 2e 65 78 65 } //01 00  gbpsv.exe
		$a_01_4 = {43 3a 5c 61 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 53 63 70 61 64 } //00 00  C:\arquivos de programas\Scpad
		$a_00_5 = {5d 04 00 00 } //69 63 
	condition:
		any of ($a_*)
 
}