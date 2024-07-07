
rule TrojanDownloader_O97M_Donoff_BQ{
	meta:
		description = "TrojanDownloader:O97M/Donoff.BQ,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {53 68 65 6c 6c 45 78 65 63 75 74 65 28 30 2c 20 22 6f 70 65 6e 22 2c 20 22 63 65 72 74 75 74 69 6c 2e 65 78 65 22 2c 20 22 2d 64 65 63 6f 64 65 } //1 ShellExecute(0, "open", "certutil.exe", "-decode
	condition:
		((#a_00_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_BQ_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.BQ,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {22 5c 73 63 61 6c 65 64 2e 65 78 65 22 } //2 "\scaled.exe"
		$a_00_1 = {22 71 75 61 64 72 69 66 6f 6c 69 6f 6c 61 74 65 } //1 "quadrifoliolate
		$a_00_2 = {45 78 65 63 51 75 65 72 79 28 22 53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 57 49 4e 33 32 5f 50 72 6f 64 75 63 74 20 57 48 45 52 45 20 4e 61 6d 65 20 4c 49 4b 45 20 27 50 79 74 68 6f 6e 20 25 } //1 ExecQuery("Select * from WIN32_Product WHERE Name LIKE 'Python %
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_BQ_3{
	meta:
		description = "TrojanDownloader:O97M/Donoff.BQ,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {52 44 42 4e 72 65 36 57 20 3d 20 51 65 4f 47 57 74 7a 41 5a 39 62 32 75 33 5a 20 2d 20 28 28 51 65 4f 47 57 74 7a 41 5a 39 62 32 75 33 5a 20 5c 20 49 6c 34 62 79 62 5a 31 75 45 37 29 20 2a 20 49 6c 34 62 79 62 5a 31 75 45 37 29 } //1 RDBNre6W = QeOGWtzAZ9b2u3Z - ((QeOGWtzAZ9b2u3Z \ Il4bybZ1uE7) * Il4bybZ1uE7)
		$a_00_1 = {71 69 32 50 44 44 71 31 77 20 3d 20 28 52 38 43 35 39 61 46 67 42 20 2d 20 53 39 73 62 6d 6c 55 6e 49 75 43 29 20 2f 20 4b 78 77 53 31 48 36 39 4c 6b 57 31 58 6f 28 4c 6e 34 32 69 79 59 29 } //1 qi2PDDq1w = (R8C59aFgB - S9sbmlUnIuC) / KxwS1H69LkW1Xo(Ln42iyY)
		$a_00_2 = {59 4c 42 4b 41 39 53 76 6a 34 43 28 6f 6c 49 30 36 62 57 59 69 38 58 6b 4b 2c 20 28 67 58 64 78 6e 43 4c 44 59 52 30 4e 65 42 64 20 2a 20 53 39 73 62 6d 6c 55 6e 49 75 43 29 20 2b 20 47 45 6e 6c 58 4d 51 33 70 51 79 29 } //1 YLBKA9Svj4C(olI06bWYi8XkK, (gXdxnCLDYR0NeBd * S9sbmlUnIuC) + GEnlXMQ3pQy)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}