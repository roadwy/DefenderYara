
rule TrojanDownloader_O97M_Powdow_SIK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SIK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 5e 70 50 22 20 2b 20 22 5a 5e 44 5e 4a 5e 44 22 20 2b 20 22 5e 62 2f 5e 6d 6f 63 22 20 2b 20 22 2e 5e 68 74 22 20 2b 20 22 6c 61 5e 65 68 22 20 2b 20 22 5e 6f 72 22 20 2b 20 22 5e 70 6f 66 6e 22 20 2b 20 22 69 2f 2f 3a 70 22 20 2b 20 22 74 5e 74 5e 68 5e 40 22 20 2b 20 22 5e 22 } //1 = "^pP" + "Z^D^J^D" + "^b/^moc" + ".^ht" + "la^eh" + "^or" + "^pofn" + "i//:p" + "t^t^h^@" + "^"
	condition:
		((#a_01_0  & 1)*1) >=1
 
}