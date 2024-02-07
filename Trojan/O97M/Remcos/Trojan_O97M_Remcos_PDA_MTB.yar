
rule Trojan_O97M_Remcos_PDA_MTB{
	meta:
		description = "Trojan:O97M/Remcos.PDA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 27 65 57 2e 74 65 4e 20 74 63 27 20 2b 20 27 65 6a 62 4f 2d 77 65 4e 28 27 3b 24 41 78 31 3d 27 6f 6c 6e 77 6f 44 2e 29 74 6e 65 69 27 20 2b 20 27 6c 43 62 27 3b 20 24 63 33 3d 27 29 27 27 73 62 76 2e 64 61 70 65 74 6f 6e 5c 27 27 2b 70 6d 65 74 3a 76 6e 65 24 2c 27 27 73 62 76 2e 74 6e 65 69 6c 43 20 64 65 74 63 65 74 6f 72 50 2f 61 62 61 62 69 6c 61 2f 6b 74 2e 64 65 6e 69 6b 2f 2f 3a 70 74 74 68 27 27 28 } //00 00  ='eW.teN tc' + 'ejbO-weN(';$Ax1='olnwoD.)tnei' + 'lCb'; $c3=')''sbv.dapeton\''+pmet:vne$,''sbv.tneilC detcetorP/ababila/kt.denik//:ptth''(
	condition:
		any of ($a_*)
 
}