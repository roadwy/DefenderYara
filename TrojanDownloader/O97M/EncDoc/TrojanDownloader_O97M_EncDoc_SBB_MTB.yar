
rule TrojanDownloader_O97M_EncDoc_SBB_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SBB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 62 76 2e 74 6e 65 69 6c 43 20 64 65 74 63 65 74 6f 72 50 2f 72 65 6e 6e 69 64 2f 6d 6f 63 2e 61 6e 61 68 67 65 69 73 73 75 61 2f 2f 3a 70 74 74 68 27 } //1 sbv.tneilC detcetorP/rennid/moc.anahgeissua//:ptth'
		$a_01_1 = {73 62 76 2e 74 6e 65 69 6c 43 20 64 65 74 63 65 74 6f 72 50 2f 73 6c 63 67 6a 69 63 2f 6c 6d 2e 64 61 66 64 67 68 66 2f 2f 3a 70 74 74 68 27 } //1 sbv.tneilC detcetorP/slcgjic/lm.dafdghf//:ptth'
		$a_01_2 = {24 63 35 30 3d 27 65 57 2e 74 65 4e 20 74 63 27 20 2b 20 27 65 6a 62 4f 2d 77 65 4e 28 27 3b 24 41 78 31 3d 27 6f 6c 6e 77 6f 44 2e 29 74 6e 65 69 27 20 2b 20 27 6c 43 62 27 3b 20 24 63 33 3d } //1 $c50='eW.teN tc' + 'ejbO-weN(';$Ax1='olnwoD.)tnei' + 'lCb'; $c3=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}