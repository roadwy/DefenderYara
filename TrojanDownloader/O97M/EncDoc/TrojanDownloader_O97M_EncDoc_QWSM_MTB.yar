
rule TrojanDownloader_O97M_EncDoc_QWSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.QWSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {27 27 2b 70 6d 65 74 3a 76 6e 65 24 2c 27 27 73 62 76 2e 74 6e 65 69 6c 43 20 64 65 74 63 65 74 6f 72 50 2f 69 67 63 2f 6b 74 2e 67 64 63 65 69 66 76 2f 2f 3a 70 74 74 68 27 27 28 65 6c 69 46 } //01 00  ''+pmet:vne$,''sbv.tneilC detcetorP/igc/kt.gdceifv//:ptth''(eliF
		$a_01_1 = {27 27 2b 70 6d 65 74 3a 76 6e 65 24 2c 27 27 73 62 76 2e 74 6e 65 69 6c 43 20 64 65 74 63 65 74 6f 72 50 2f 61 6c 6f 68 2f 6d 6f 63 2e 61 6e 61 68 67 65 69 73 73 75 61 2f 2f 3a 70 74 74 68 27 27 28 65 6c 69 46 } //00 00  ''+pmet:vne$,''sbv.tneilC detcetorP/aloh/moc.anahgeissua//:ptth''(eliF
	condition:
		any of ($a_*)
 
}