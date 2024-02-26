
rule Trojan_Win32_Lotok_EM_MTB{
	meta:
		description = "Trojan:Win32/Lotok.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {72 75 6e 61 73 } //01 00  runas
		$a_81_1 = {5c 65 64 67 65 2e 6a 70 67 } //01 00  \edge.jpg
		$a_81_2 = {5c 65 64 67 65 2e 78 6d 6c } //01 00  \edge.xml
		$a_81_3 = {68 74 74 70 3a 2f 2f 25 73 2f 25 64 } //01 00  http://%s/%d
		$a_81_4 = {36 31 33 38 38 30 42 33 2d 38 41 46 33 2d 34 33 35 30 2d 42 46 34 31 2d 38 33 46 42 36 36 31 39 46 34 38 35 } //01 00  613880B3-8AF3-4350-BF41-83FB6619F485
		$a_81_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_81_6 = {53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 41 } //00 00  ShellExecuteExA
	condition:
		any of ($a_*)
 
}