
rule TrojanDownloader_O97M_Donoff_OBSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.OBSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 61 70 70 64 61 74 61 25 22 29 26 22 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 73 74 61 72 74 6d 65 6e 75 5c 70 72 6f 67 72 61 6d 73 5c 73 74 61 72 74 75 70 5c 75 70 64 61 74 65 73 79 6e 63 69 6e 67 2e 62 61 74 22 2c 32 2c 74 72 75 65 29 } //01 00  %appdata%")&"\microsoft\windows\startmenu\programs\startup\updatesyncing.bat",2,true)
		$a_01_1 = {63 6d 64 3d 22 63 6d 64 2f 63 73 74 61 72 74 2f 62 2f 6d 69 6e 22 26 22 63 3a 5c 77 69 6e 64 22 26 22 6f 77 73 5c 6d 69 63 72 22 26 22 6f 73 6f 66 74 2e 6e 65 74 5c 66 72 61 6d 65 77 22 26 22 6f 72 6b 36 34 5c 76 34 2e 30 2e 33 22 26 22 30 33 31 39 5c 6d 73 62 75 22 26 22 69 6c 64 2e 65 78 65 22 26 22 2f 6e 6f 6c 22 26 22 6f 67 6f 2f 6e 6f 63 6f 6e 73 22 26 22 6f 6c 65 6c 6f 67 67 65 72 22 26 73 74 72 72 65 73 75 6c 74 } //01 00  cmd="cmd/cstart/b/min"&"c:\wind"&"ows\micr"&"osoft.net\framew"&"ork64\v4.0.3"&"0319\msbu"&"ild.exe"&"/nol"&"ogo/nocons"&"olelogger"&strresult
		$a_01_2 = {73 62 6d 62 3d 22 34 63 38 62 64 63 34 39 38 39 35 62 30 38 22 } //01 00  sbmb="4c8bdc49895b08"
		$a_01_3 = {73 73 6d 62 3d 22 34 38 38 33 65 63 33 38 34 35 33 33 64 62 22 } //01 00  ssmb="4883ec384533db"
		$a_01_4 = {73 62 6d 62 3d 22 38 62 34 35 30 63 38 35 63 30 37 34 35 61 38 35 64 62 22 } //01 00  sbmb="8b450c85c0745a85db"
		$a_01_5 = {73 73 6d 62 3d 22 38 62 35 35 30 63 38 35 64 32 37 34 33 34 38 33 37 64 22 } //00 00  ssmb="8b550c85d27434837d"
	condition:
		any of ($a_*)
 
}