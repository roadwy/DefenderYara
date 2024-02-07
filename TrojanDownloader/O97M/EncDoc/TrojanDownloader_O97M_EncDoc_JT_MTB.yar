
rule TrojanDownloader_O97M_EncDoc_JT_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.JT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 68 74 74 70 3a 2f 2f 64 6f 63 2e 77 69 6b 69 7a 65 65 2e 63 6f 6d 2f } //01 00  = "http://doc.wikizee.com/
		$a_01_1 = {26 20 22 61 2f 64 6f 63 } //01 00  & "a/doc
		$a_01_2 = {3e 20 22 20 26 20 74 65 6d 70 20 26 20 22 5c 39 33 30 32 38 30 61 2d 64 6f 63 } //01 00  > " & temp & "\930280a-doc
		$a_01_3 = {3d 20 22 63 6d 64 2e 65 78 65 20 2f 4b 20 63 75 72 6c 20 2d 41 } //01 00  = "cmd.exe /K curl -A
		$a_01_4 = {43 61 6c 6c 20 53 68 65 6c 6c 28 66 2c 20 76 62 48 69 64 65 29 } //00 00  Call Shell(f, vbHide)
	condition:
		any of ($a_*)
 
}