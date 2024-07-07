
rule TrojanDownloader_O97M_Powdow_PDO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PDO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 46 53 4f 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 58 4f 52 45 6e 63 72 79 70 74 69 6f 6e 28 } //1 Set FSO = GetObject(XOREncryption(
		$a_01_1 = {46 53 4f 2e 63 6f 70 79 66 69 6c 65 20 58 4f 52 45 6e 63 72 79 70 74 69 6f 6e 28 } //1 FSO.copyfile XOREncryption(
		$a_01_2 = {73 65 65 20 3d 20 22 61 6a 73 64 6a 61 77 69 64 75 61 69 77 64 75 61 69 75 64 69 61 77 75 22 } //1 see = "ajsdjawiduaiwduaiudiawu"
		$a_01_3 = {53 68 65 6c 6c 20 45 6e 76 69 72 6f 6e 28 22 50 55 42 4c 49 43 22 29 20 26 20 22 5c 63 61 6c 63 2e 63 6f 6d 22 20 2b 20 6d 6f 6b 61 20 2b 20 73 65 65 2c 20 76 62 48 69 64 65 } //1 Shell Environ("PUBLIC") & "\calc.com" + moka + see, vbHide
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}