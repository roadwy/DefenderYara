
rule TrojanDownloader_O97M_Powdow_BBQA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BBQA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 57 2e 74 65 4e 20 74 63 27 20 2b 20 27 65 6a 62 4f 2d 77 65 4e 28 27 3b 20 24 62 34 64 66 3d 27 6f 6c 6e 77 6f 44 2e 29 74 6e 65 69 27 20 2b 20 27 6c 43 62 27 3b 20 24 63 33 3d 27 29 27 27 73 62 76 2e 73 64 61 70 65 74 6f 6e 5c 27 27 2b 70 6d 65 74 3a 76 6e 65 24 2c 27 27 73 62 76 2e 74 6e 65 69 6c 43 2f 63 61 6d 2f 6c 72 70 73 77 2f 6d 6f 63 2e 65 68 67 69 74 79 65 6e 6e 69 6b 63 6d 2f 2f 3a } //00 00  eW.teN tc' + 'ejbO-weN('; $b4df='olnwoD.)tnei' + 'lCb'; $c3=')''sbv.sdapeton\''+pmet:vne$,''sbv.tneilC/cam/lrpsw/moc.ehgityennikcm//:
	condition:
		any of ($a_*)
 
}