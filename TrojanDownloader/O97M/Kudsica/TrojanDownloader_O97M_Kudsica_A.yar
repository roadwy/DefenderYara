
rule TrojanDownloader_O97M_Kudsica_A{
	meta:
		description = "TrojanDownloader:O97M/Kudsica.A,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 72 69 6e 74 20 23 46 69 6c 65 4e 75 6d 62 65 72 2c 20 22 24 64 6f 77 6e 20 3d 20 4e 22 20 26 20 22 65 77 22 20 26 20 22 2d 22 20 26 20 43 68 72 28 37 39 29 20 26 20 22 62 6a 65 63 74 20 53 79 22 20 26 20 22 73 74 65 6d 2e 22 20 26 20 43 68 72 28 37 38 29 20 26 20 22 65 74 2e 22 20 26 20 43 68 72 28 38 37 29 20 26 20 22 65 62 22 20 26 20 22 43 6c 69 22 20 26 20 22 65 6e 74 3b 22 } //01 00  Print #FileNumber, "$down = N" & "ew" & "-" & Chr(79) & "bject Sy" & "stem." & Chr(78) & "et." & Chr(87) & "eb" & "Cli" & "ent;"
		$a_01_1 = {4d 59 5f 46 49 4c 44 49 52 20 3d 20 22 63 3a 5c 77 69 6e 64 6f 77 73 5c 74 65 6d 70 22 20 2b 20 22 5c 61 64 6f 62 65 61 63 64 2d 75 70 64 61 74 65 2e 22 20 26 20 43 68 72 28 31 31 38 29 20 26 20 22 62 22 20 26 20 22 73 } //01 00  MY_FILDIR = "c:\windows\temp" + "\adobeacd-update." & Chr(118) & "b" & "s
		$a_01_2 = {50 72 69 6e 74 20 23 46 69 6c 65 4e 75 6d 62 65 72 2c 20 22 24 66 69 6c 65 31 2e 41 74 74 72 69 62 75 74 65 73 20 3d 20 24 66 69 6c 65 31 2e 41 74 74 72 69 62 75 74 65 73 20 2d 62 78 6f 72 20 5b 53 79 73 74 65 6d 2e 49 4f 2e 46 69 6c 65 41 74 74 72 69 62 75 74 65 73 5d 3a 3a 48 69 64 64 65 6e } //01 00  Print #FileNumber, "$file1.Attributes = $file1.Attributes -bxor [System.IO.FileAttributes]::Hidden
		$a_01_3 = {4d 59 5f 46 49 4c 45 44 49 52 20 3d 20 22 63 3a 5c 55 73 65 72 73 5c 22 20 2b 20 55 53 45 52 20 2b 20 22 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //01 00  MY_FILEDIR = "c:\Users\" + USER + "\AppData\Local\Temp
		$a_01_4 = {50 72 69 6e 74 20 23 46 69 6c 65 4e 75 6d 62 65 72 2c 20 22 73 74 72 46 69 6c 65 55 52 4c 20 3d 20 22 20 2b 20 43 68 72 28 33 34 29 20 2b 20 22 68 74 74 70 3a } //01 00  Print #FileNumber, "strFileURL = " + Chr(34) + "http:
		$a_01_5 = {50 72 69 6e 74 20 23 46 69 6c 65 4e 75 6d 62 65 72 2c 20 22 53 65 74 20 6f 62 6a 58 4d 4c 48 54 54 50 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 } //00 00  Print #FileNumber, "Set objXMLHTTP = CreateObject(
	condition:
		any of ($a_*)
 
}