
rule TrojanDownloader_O97M_Bartallex_C{
	meta:
		description = "TrojanDownloader:O97M/Bartallex.C,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {69 6e 2e 63 6f 6d 2f 72 61 77 2e 70 68 70 3f 69 3d } //01 00  in.com/raw.php?i=
		$a_00_1 = {2f 75 73 2f 66 69 6c 65 22 20 2b 20 53 58 45 } //01 00  /us/file" + SXE
		$a_00_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 53 58 4d 4c 32 2e 53 65 72 76 65 72 58 4d 4c 48 54 54 50 22 29 } //00 00  CreateObject("MSXML2.ServerXMLHTTP")
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Bartallex_C_2{
	meta:
		description = "TrojanDownloader:O97M/Bartallex.C,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 70 65 6e 20 4d 59 5f 46 49 4c 44 49 52 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 } //01 00  Open MY_FILDIR For Output As
		$a_01_1 = {4d 6f 64 75 6c 65 31 2e } //01 00  Module1.
		$a_01_2 = {63 69 6e 74 6f 73 68 3b 20 49 6e 74 65 6c 20 4d 61 63 20 4f 53 20 58 } //01 00  cintosh; Intel Mac OS X
		$a_01_3 = {43 68 72 28 33 34 } //01 00  Chr(34
		$a_01_4 = {43 68 72 28 31 31 31 } //00 00  Chr(111
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Bartallex_C_3{
	meta:
		description = "TrojanDownloader:O97M/Bartallex.C,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {22 70 69 22 20 2b 20 22 6e 67 20 31 2e 31 2e 32 2e 32 20 2d 6e 22 20 26 20 22 20 32 22 } //01 00  "pi" + "ng 1.1.2.2 -n" & " 2"
		$a_01_1 = {22 64 65 6c 20 22 20 2b 20 43 68 72 28 33 34 29 20 2b 20 22 63 22 20 26 20 22 3a 5c 22 20 26 20 22 57 22 20 26 20 22 69 6e 64 22 20 26 20 22 6f 77 73 5c 54 22 20 26 20 22 65 6d 22 20 26 20 22 70 5c 22 20 2b 20 43 68 72 28 33 34 29 20 2b 20 22 25 74 61 72 31 25 22 20 2b 20 22 22 20 26 20 22 22 } //01 00  "del " + Chr(34) + "c" & ":\" & "W" & "ind" & "ows\T" & "em" & "p\" + Chr(34) + "%tar1%" + "" & ""
		$a_01_2 = {28 22 77 69 6e 6d 67 6d 74 73 3a 7b 69 6d 70 65 72 73 6f 6e 61 74 69 6f 6e 4c 65 76 65 6c 3d 69 6d 70 65 72 73 6f 6e 61 74 65 7d 21 5c 5c 22 20 26 20 22 2e 5c 72 6f 6f 74 5c 63 69 6d 76 32 22 29 } //00 00  ("winmgmts:{impersonationLevel=impersonate}!\\" & ".\root\cimv2")
	condition:
		any of ($a_*)
 
}