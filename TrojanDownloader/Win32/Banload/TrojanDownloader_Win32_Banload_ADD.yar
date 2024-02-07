
rule TrojanDownloader_Win32_Banload_ADD{
	meta:
		description = "TrojanDownloader:Win32/Banload.ADD,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {c2 08 00 53 a1 90 01 04 83 38 00 74 90 01 01 8b 1d 90 01 04 8b 1b ff d3 5b c3 90 01 01 55 8b ec 51 53 56 57 89 4d fc 8b da 8b f0 8b c3 ff 50 f4 90 00 } //01 00 
		$a_00_1 = {49 45 28 41 4c 28 22 25 73 22 2c 34 29 2c 22 41 4c 28 5c 22 25 30 3a 73 5c 22 2c 33 29 22 2c 22 4a 4b 28 5c 22 25 31 3a 73 5c 22 2c 5c 22 25 30 3a 73 5c 22 29 22 29 } //01 00  IE(AL("%s",4),"AL(\"%0:s\",3)","JK(\"%1:s\",\"%0:s\")")
		$a_00_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 54 65 6d 70 5c 61 73 79 74 77 73 2e 65 78 65 } //01 00  C:\WINDOWS\Temp\asytws.exe
		$a_00_3 = {68 64 66 72 65 65 2e 63 6f 6d 2e 62 72 } //00 00  hdfree.com.br
	condition:
		any of ($a_*)
 
}