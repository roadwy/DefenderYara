
rule TrojanSpy_Win32_Banker_HG{
	meta:
		description = "TrojanSpy:Win32/Banker.HG,SIGNATURE_TYPE_PEHSTR_EXT,2a 00 2a 00 08 00 00 0a 00 "
		
	strings :
		$a_02_0 = {57 69 6e 64 6f 77 73 75 70 64 61 74 65 31 68 90 01 10 57 69 6e 64 6f 77 73 6d 65 73 73 65 6e 67 65 72 31 70 90 00 } //0a 00 
		$a_00_1 = {57 4e 65 74 47 65 74 43 6f 6e 6e 65 63 74 69 6f 6e 41 } //0a 00  WNetGetConnectionA
		$a_00_2 = {52 65 67 53 65 74 56 61 6c 75 65 45 78 41 } //0a 00  RegSetValueExA
		$a_00_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_00_4 = {69 6d 67 49 74 61 75 43 6c 69 63 6b } //01 00  imgItauClick
		$a_00_5 = {43 6f 6e 66 69 67 75 72 61 6f 64 65 62 6c 6f 71 75 65 61 64 6f 72 64 65 70 6f 70 75 70 73 } //01 00  Configuraodebloqueadordepopups
		$a_00_6 = {57 69 6e 64 6f 77 73 6d 65 73 73 65 6e 67 65 72 31 34 } //01 00  Windowsmessenger14
		$a_00_7 = {45 6d 61 69 6c 65 6e 6f 74 63 69 61 73 31 40 } //00 00  Emailenotcias1@
	condition:
		any of ($a_*)
 
}