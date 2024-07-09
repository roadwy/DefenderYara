
rule TrojanDownloader_O97M_Powdow_SCS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SCS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 6f 6b 6f 61 6b 29 } //1 = CreateObject(okoak)
		$a_01_1 = {46 42 53 2e 63 6f 70 79 66 69 6c 65 20 61 64 6f 6f 2c 20 45 6e 76 69 72 6f 6e 24 28 6a 61 6c 75 6b 61 29 20 26 20 22 5c 6c 6f 22 20 2b 20 22 76 65 2e 63 6f 22 20 2b 20 53 74 72 69 6e 67 28 31 2c 20 22 6d 22 29 2c 20 54 72 75 65 } //1 FBS.copyfile adoo, Environ$(jaluka) & "\lo" + "ve.co" + String(1, "m"), True
		$a_01_2 = {3d 20 53 70 6c 69 74 28 22 6b 65 69 6f 61 6b 6b 6a 65 6b 65 69 6f 61 6b 6b 6a 65 6b 65 69 6f 61 6b 6b 6a 65 6b 65 69 6f 61 6b 6b 6a 65 6b 65 69 6f 61 6b 6b 6a 65 6b 65 69 6f 61 6b 6b 6a 65 6b 65 69 6f 61 6b 6b 6a 65 6b 65 69 6f 61 6b 6b 6a 65 } //1 = Split("keioakkjekeioakkjekeioakkjekeioakkjekeioakkjekeioakkjekeioakkjekeioakkje
		$a_03_3 = {3d 20 4a 6f 69 6e 28 63 6f 6f 70 65 72 2c 20 22 22 29 20 2b 20 69 64 63 61 72 64 73 20 2b 20 22 ?? ?? 22 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}