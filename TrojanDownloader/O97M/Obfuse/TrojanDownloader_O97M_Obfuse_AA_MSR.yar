
rule TrojanDownloader_O97M_Obfuse_AA_MSR{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.AA!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 20 55 73 65 72 46 6f 72 6d 31 2e 54 65 78 74 42 6f 78 31 2e 54 65 78 74 } //1 = UserForm1.TextBox1.Text
		$a_01_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //1 = CreateObject("Scripting.FileSystemObject")
		$a_01_2 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 42 4f 45 55 44 49 44 49 53 2c 20 54 72 75 65 2c 20 54 72 75 65 29 } //1 .CreateTextFile(BOEUDIDIS, True, True)
		$a_01_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 = CreateObject("Shell.Application")
		$a_01_4 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 42 4f 45 55 44 49 44 49 53 } //1 .ShellExecute BOEUDIDIS
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Obfuse_AA_MSR_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.AA!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {5a 6a 6b 6b 6a 77 76 79 67 69 6c 20 3d 20 53 67 6e 28 22 48 75 64 73 6f 6e 20 47 72 6f 75 70 41 70 74 2e 20 35 36 33 4e 6f 72 74 68 22 29 } //1 Zjkkjwvygil = Sgn("Hudson GroupApt. 563North")
		$a_00_1 = {50 71 71 76 6a 69 6a 62 76 73 20 3d 20 48 65 78 28 37 37 29 } //1 Pqqvjijbvs = Hex(77)
		$a_00_2 = {56 76 69 6c 63 6c 6a 76 6e 20 3d 20 4f 63 74 28 22 53 61 6c 61 64 22 29 } //1 Vvilcljvn = Oct("Salad")
		$a_00_3 = {4a 63 75 62 6d 78 69 67 76 6c 73 20 3d 20 49 6e 74 28 22 53 70 65 6e 63 65 72 20 2d 20 50 72 69 63 65 41 70 74 2e 20 39 37 35 53 6f 75 74 68 77 65 73 74 22 29 } //1 Jcubmxigvls = Int("Spencer - PriceApt. 975Southwest")
		$a_00_4 = {46 71 76 6a 6a 73 7a 63 20 3d 20 43 44 61 74 65 28 22 52 61 74 6b 65 20 61 6e 64 20 53 6f 6e 73 53 75 69 74 65 20 32 30 31 53 6f 75 74 68 22 29 } //1 Fqvjjszc = CDate("Ratke and SonsSuite 201South")
		$a_00_5 = {4e 69 7a 62 66 78 6d 64 20 3d 20 48 65 78 28 22 53 69 70 65 73 20 2d 20 42 72 61 64 74 6b 65 41 70 74 2e 20 38 33 31 4e 6f 72 74 68 77 65 73 74 22 29 } //1 Nizbfxmd = Hex("Sipes - BradtkeApt. 831Northwest")
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}