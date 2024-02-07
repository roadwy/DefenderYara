
rule TrojanDownloader_Win32_Carrobat_A{
	meta:
		description = "TrojanDownloader:Win32/Carrobat.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 3a 20 26 26 20 63 64 20 25 54 45 4d 50 25 20 26 26 20 63 5e 65 5e 72 5e 74 75 74 69 6c 20 2d 75 72 6c 63 61 5e 63 68 65 20 2d 73 70 6c } //01 00  C: && cd %TEMP% && c^e^r^tutil -urlca^che -spl
		$a_02_1 = {69 74 20 2d 66 20 68 74 74 70 90 02 02 3a 2f 2f 90 02 20 61 70 90 02 01 70 90 02 02 2e 63 6f 6d 90 02 10 2f 31 2e 74 78 74 20 26 26 20 72 65 6e 20 31 2e 74 78 74 20 31 2e 62 61 74 90 00 } //01 00 
		$a_00_2 = {26 26 20 31 2e 62 61 74 20 26 26 20 65 78 69 74 } //00 00  && 1.bat && exit
	condition:
		any of ($a_*)
 
}