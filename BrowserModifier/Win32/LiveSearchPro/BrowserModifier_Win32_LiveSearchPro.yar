
rule BrowserModifier_Win32_LiveSearchPro{
	meta:
		description = "BrowserModifier:Win32/LiveSearchPro,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 69 76 65 53 65 61 72 63 68 50 72 6f 20 56 65 72 2e } //01 00  LiveSearchPro Ver.
		$a_01_1 = {7b 34 44 35 30 32 35 46 33 2d 46 33 44 41 2d 34 33 30 30 2d 42 35 39 38 2d 44 34 35 44 33 37 41 44 41 37 34 43 7d } //01 00  {4D5025F3-F3DA-4300-B598-D45D37ADA74C}
		$a_01_2 = {6f 66 66 69 6d 61 74 65 2e 63 6f 6d 20 68 74 74 70 3a 2f 2f 61 75 74 6f 2e 6c 69 76 65 73 65 61 72 63 68 70 72 6f 2e 63 6f 6d 2f 72 65 73 70 6f 6e 73 65 } //01 00  offimate.com http://auto.livesearchpro.com/response
		$a_01_3 = {61 63 74 69 76 65 62 72 7a 2e 65 78 65 } //02 00  activebrz.exe
		$a_01_4 = {46 61 62 6f 75 74 3a 62 6c 61 6e 6b 00 68 74 74 70 3a 00 00 00 66 69 6c 65 3a 00 00 00 4c 49 56 45 53 45 41 52 43 48 50 52 4f 54 4f 4f 4c 42 41 52 } //01 00 
		$a_01_5 = {4c 69 76 65 53 65 61 72 63 68 50 72 6f 2e 44 4c 4c } //02 00  LiveSearchPro.DLL
		$a_01_6 = {4c 69 76 65 53 65 61 72 63 68 50 72 6f 00 00 00 53 6f 66 74 77 61 72 65 5c 4b 52 41 53 50 } //00 00 
	condition:
		any of ($a_*)
 
}