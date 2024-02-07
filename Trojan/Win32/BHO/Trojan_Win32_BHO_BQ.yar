
rule Trojan_Win32_BHO_BQ{
	meta:
		description = "Trojan:Win32/BHO.BQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 68 6f 4e 65 77 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //01 00  桂乯睥䐮䱌䐀汬慃啮汮慯乤睯
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 73 65 65 6b 6e 65 77 6c 69 76 65 2e 63 6f 6d 2f 62 61 72 2f 65 6e 2e 6a 73 } //01 00  http://www.seeknewlive.com/bar/en.js
		$a_01_2 = {3c 69 6d 67 20 68 65 69 67 68 74 3d 30 20 77 69 64 74 68 3d 30 20 73 74 79 6c 65 3d } //00 00  <img height=0 width=0 style=
	condition:
		any of ($a_*)
 
}