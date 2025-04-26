
rule TrojanDownloader_O97M_Donoff_BB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.BB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 73 67 42 6f 78 20 64 65 63 72 79 70 74 28 58 4f 52 45 6e 63 72 79 70 74 69 6f 6e 28 } //1 MsgBox decrypt(XOREncryption(
		$a_01_1 = {58 4f 52 45 6e 63 72 79 70 74 69 6f 6e 20 3d 20 58 4f 52 45 6e 63 72 79 70 74 69 6f 6e 20 26 20 43 68 72 28 41 73 63 28 4d 69 64 28 73 4b 65 79 2c 20 49 49 66 28 69 20 4d 6f 64 20 4c 65 6e 28 73 4b 65 79 29 20 3c 3e 20 30 2c 20 69 20 4d 6f 64 20 4c 65 6e 28 73 4b 65 79 29 2c 20 4c 65 6e 28 73 4b 65 79 29 29 2c 20 31 29 29 20 58 6f 72 20 41 73 63 28 4d 69 64 28 73 53 74 72 2c 20 69 2c 20 31 29 29 29 } //1 XOREncryption = XOREncryption & Chr(Asc(Mid(sKey, IIf(i Mod Len(sKey) <> 0, i Mod Len(sKey), Len(sKey)), 1)) Xor Asc(Mid(sStr, i, 1)))
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}