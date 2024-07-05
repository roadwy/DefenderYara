
rule TrojanDownloader_O97M_Obfuse_AB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.AB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } //01 00  Sub autoopen()
		$a_01_1 = {2e 43 72 65 61 74 65 46 6f 6c 64 65 72 20 22 63 3a 5c 31 22 } //01 00  .CreateFolder "c:\1"
		$a_01_2 = {42 65 6e 61 6a 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 63 3a 5c 31 5c 53 49 4e 47 41 50 4f 55 52 2e 63 6d 64 22 } //01 00  Benaj.CreateTextFile("c:\1\SINGAPOUR.cmd"
		$a_01_3 = {42 65 6e 61 6a 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 63 3a 5c 31 5c 46 52 41 4e 43 45 2e 63 6d 64 22 } //01 00  Benaj.CreateTextFile("c:\1\FRANCE.cmd"
		$a_01_4 = {41 72 63 68 69 74 65 63 74 75 72 65 2e 57 72 69 74 65 4c 69 6e 65 20 28 22 62 72 65 61 6b 3e 25 46 6f 6c 64 65 72 56 42 53 25 22 29 } //01 00  Architecture.WriteLine ("break>%FolderVBS%")
		$a_01_5 = {28 22 73 74 61 72 74 20 63 3a 5c 31 5c 57 6f 6d 61 6e 4c 6f 76 65 2e 65 78 65 22 29 } //00 00  ("start c:\1\WomanLove.exe")
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_AB_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.AB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_80_0 = {43 61 6c 6c 20 53 68 65 6c 6c 28 6d 61 72 72 73 65 6c 6c 20 2b 20 73 64 65 6d 6f 6d 20 26 20 64 61 62 73 61 } //Call Shell(marrsell + sdemom & dabsa  01 00 
		$a_80_1 = {53 74 72 20 3d 20 22 7b 31 32 7d 7b 31 36 7d 7b 31 35 7d 7b 32 31 7d 7b 31 34 7d 7b 39 7d 7b 32 30 7d 7b 31 30 7d 7b 37 7d 7b 31 39 7d 7b 32 32 7d 7b 31 7d 7b 36 7d 7b 33 7d 7b 32 7d 7b 31 37 7d 7b 34 7d 7b 32 33 7d 7b 31 33 7d 7b 30 7d 7b 32 34 7d 7b 32 35 7d 7b 31 31 7d 7b 38 7d 7b 35 7d 7b 31 38 7d 3b 2e 28 55 43 41 7b 31 7d } //Str = "{12}{16}{15}{21}{14}{9}{20}{10}{7}{19}{22}{1}{6}{3}{2}{17}{4}{23}{13}{0}{24}{25}{11}{8}{5}{18};.(UCA{1}  01 00 
		$a_80_2 = {53 74 72 20 3d 20 73 53 72 74 20 2b 20 22 30 7d 28 5b 63 48 41 52 5d 38 35 2b 5b 63 48 41 52 5d 36 37 2b 5b 63 48 41 52 5d 36 35 29 2c 5b 63 48 41 52 5d 33 34 29 29 } //Str = sSrt + "0}([cHAR]85+[cHAR]67+[cHAR]65),[cHAR]34))  01 00 
		$a_80_3 = {46 75 6e 63 74 69 6f 6e 20 73 65 74 74 6c 65 72 28 29 } //Function settler()  01 00 
		$a_80_4 = {73 65 74 74 6c 65 72 20 3d 20 22 43 4d 44 2e 45 78 65 } //settler = "CMD.Exe  01 00 
		$a_80_5 = {46 75 6e 63 74 69 6f 6e 20 63 6f 6d 6d 64 65 28 29 } //Function commde()  01 00 
		$a_80_6 = {46 75 6e 63 74 69 6f 6e 20 63 72 73 73 73 28 29 } //Function crsss()  01 00 
		$a_80_7 = {41 6e 64 50 6c 75 73 20 3d 20 73 65 74 74 6c 65 72 20 2b 20 64 6f 75 62 6c 65 63 68 65 63 6b 20 2b 20 66 6f 72 6d 73 61 6e 64 73 20 2b 20 63 6c 65 61 72 64 61 74 61 73 20 2b 20 63 6f 6d 6d 64 65 20 2b 20 63 72 73 73 73 } //AndPlus = settler + doublecheck + formsands + cleardatas + commde + crsss  00 00 
	condition:
		any of ($a_*)
 
}