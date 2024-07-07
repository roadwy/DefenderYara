
rule TrojanDownloader_O97M_Qakbot_BQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.BQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 49 59 54 47 47 44 55 47 48 44 46 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4f 49 55 54 46 75 79 22 2c 20 54 72 75 65 29 } //1 = IYTGGDUGHDF.CreateTextFile("C:\ProgramData\OIUTFuy", True)
		$a_01_1 = {2e 45 78 65 63 20 22 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 22 20 26 20 48 45 54 52 49 4f 4f 55 49 44 42 44 54 59 46 54 46 46 53 44 46 44 2e 44 65 66 61 75 6c 74 54 61 72 67 65 74 46 72 61 6d 65 } //1 .Exec "explorer.exe " & HETRIOOUIDBDTYFTFFSDFD.DefaultTargetFrame
		$a_01_2 = {2e 57 72 69 74 65 4c 69 6e 65 20 28 22 4a 65 72 69 6e 54 72 61 22 29 } //1 .WriteLine ("JerinTra")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Qakbot_BQ_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.BQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 49 59 54 47 47 44 55 47 48 44 46 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4f 49 55 54 46 75 79 22 2c 20 54 72 75 65 29 } //1 = IYTGGDUGHDF.CreateTextFile("C:\ProgramData\OIUTFuy", True)
		$a_01_1 = {2e 45 78 65 63 20 22 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 22 20 26 20 47 46 46 47 48 46 4b 46 4b 66 66 66 6b 66 64 6b 64 66 44 66 64 74 79 64 78 2e 44 65 66 61 75 6c 74 54 61 72 67 65 74 46 72 61 6d 65 } //1 .Exec "explorer.exe " & GFFGHFKFKfffkfdkdfDfdtydx.DefaultTargetFrame
		$a_01_2 = {2e 57 72 69 74 65 4c 69 6e 65 20 28 22 27 42 6f 6c 69 48 61 73 22 29 } //1 .WriteLine ("'BoliHas")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}