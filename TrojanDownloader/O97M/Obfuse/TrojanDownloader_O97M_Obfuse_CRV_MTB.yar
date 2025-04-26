
rule TrojanDownloader_O97M_Obfuse_CRV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.CRV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 61 6e 67 65 28 22 41 31 3a 4a 31 35 22 29 2e 53 65 6c 65 63 74 } //1 Range("A1:J15").Select
		$a_01_1 = {53 65 74 20 6e 6a 68 62 77 63 68 71 79 20 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 52 61 6e 67 65 28 22 41 34 22 29 2e 56 61 6c 75 65 29 } //1 Set njhbwchqy  = CreateObject(Range("A4").Value)
		$a_01_2 = {75 6b 62 64 72 64 65 7a 69 6d 6e 69 73 6a 6d 65 74 76 6a 68 7a 67 69 64 66 6f 70 6a 75 62 77 63 72 65 70 20 3d 20 52 61 6e 67 65 28 22 41 33 22 29 2e 56 61 6c 75 65 } //1 ukbdrdezimnisjmetvjhzgidfopjubwcrep = Range("A3").Value
		$a_01_3 = {52 61 6e 67 65 28 22 4d 35 22 29 2e 53 65 6c 65 63 74 } //1 Range("M5").Select
		$a_01_4 = {70 6f 6c 61 6f 74 68 69 61 20 3d 20 6e 6a 68 62 77 63 68 71 79 2e 43 72 65 61 74 65 28 75 6b 62 64 72 64 65 7a 69 6d 6e 69 73 6a 6d 65 74 76 6a 68 7a 67 69 64 66 6f 70 6a 75 62 77 63 72 65 70 29 } //1 polaothia = njhbwchqy.Create(ukbdrdezimnisjmetvjhzgidfopjubwcrep)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Obfuse_CRV_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.CRV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 49 6d 61 67 65 6d 53 69 6d 70 6c 65 73 43 44 54 2c 20 4d 61 73 74 65 72 43 44 54 20 26 20 22 64 6f 63 75 6d 65 6e 74 2e [0-03] 22 2c 20 30 2c 20 30 } //1
		$a_01_1 = {53 68 65 6c 6c 20 28 4d 5f 53 20 2b 20 54 4f 47 41 43 44 54 20 2b 20 4d 5f 53 31 20 2b 20 4d 5f 53 32 20 2b 20 4d 5f 53 33 29 2c 20 30 } //1 Shell (M_S + TOGACDT + M_S1 + M_S2 + M_S3), 0
		$a_01_2 = {50 44 66 5f 32 20 3d 20 22 65 78 65 22 22 20 2f 63 20 70 69 22 } //1 PDf_2 = "exe"" /c pi"
		$a_01_3 = {4d 61 73 74 65 72 43 44 54 20 3d 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 22 } //1 MasterCDT = "C:\Users\Public\"
		$a_01_4 = {3d 20 22 3e 20 6e 75 6c 20 26 20 73 74 61 72 74 20 43 22 } //1 = "> nul & start C"
		$a_01_5 = {52 61 62 6f 44 65 43 61 76 61 6c 6f 20 3d 20 22 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 64 6f 63 75 6d 65 6e 74 2e 22 } //1 RaboDeCavalo = ":\Users\Public\document."
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}