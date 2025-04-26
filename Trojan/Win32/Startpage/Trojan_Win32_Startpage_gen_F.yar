
rule Trojan_Win32_Startpage_gen_F{
	meta:
		description = "Trojan:Win32/Startpage.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 08 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //5 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {46 50 55 4d 61 73 6b 56 61 6c 75 65 } //5 FPUMaskValue
		$a_03_2 = {68 74 74 70 3a 2f 2f [0-03] 2e 6f 6b 75 6e 69 6f 6e 2e 63 6f 6d 2f 31 2e 74 78 74 } //5
		$a_00_3 = {53 74 61 72 74 20 50 61 67 65 } //5 Start Page
		$a_00_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //5 Software\Microsoft\Internet Explorer\Main
		$a_01_5 = {30 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 } //5 0:\Program Files\Internet Explorer\IEXPLORE.EXE
		$a_00_6 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_7 = {51 51 51 51 51 51 53 33 } //1 QQQQQQS3
	condition:
		((#a_00_0  & 1)*5+(#a_01_1  & 1)*5+(#a_03_2  & 1)*5+(#a_00_3  & 1)*5+(#a_00_4  & 1)*5+(#a_01_5  & 1)*5+(#a_00_6  & 1)*1+(#a_01_7  & 1)*1) >=32
 
}