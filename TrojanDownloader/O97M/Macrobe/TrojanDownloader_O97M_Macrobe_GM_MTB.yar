
rule TrojanDownloader_O97M_Macrobe_GM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Macrobe.GM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {58 4f 52 45 6e 63 72 79 70 74 69 6f 6e } //1 XOREncryption
		$a_00_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 7a 56 68 48 70 55 5a 4b 79 4a 77 6d 75 77 64 6c 45 6b 71 63 28 46 6f 72 74 75 6e 61 74 75 73 29 29 } //1 CreateObject(zVhHpUZKyJwmuwdlEkqc(Fortunatus))
		$a_00_2 = {43 61 6c 6c 69 73 74 6f 28 58 4f 52 45 6e 63 72 79 70 74 69 6f 6e } //1 Callisto(XOREncryption
		$a_00_3 = {58 4f 52 45 6e 63 72 79 70 74 69 6f 6e 20 3d 20 58 4f 52 45 6e 63 72 79 70 74 69 6f 6e 20 26 20 43 68 72 28 41 73 63 28 4d 69 64 28 73 4b 65 79 2c 20 49 49 66 28 69 20 4d 6f 64 20 4c 65 6e 28 73 4b 65 79 29 } //1 XOREncryption = XOREncryption & Chr(Asc(Mid(sKey, IIf(i Mod Len(sKey)
		$a_00_4 = {43 68 65 64 6f 6d 69 72 } //1 Chedomir
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}