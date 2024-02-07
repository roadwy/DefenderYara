
rule TrojanDropper_O97M_Hancitor_EOBN_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EOBN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 68 64 68 64 64 28 4c 65 66 74 28 75 75 75 75 63 2c 20 6e 74 67 73 29 20 26 20 66 61 66 61 61 29 } //01 00  Call ThisDocument.hdhdd(Left(uuuuc, ntgs) & fafaa)
		$a_01_1 = {22 5c 64 69 70 6c 6f 2e 64 22 20 26 20 61 62 72 61 6b 61 64 61 62 72 61 } //01 00  "\diplo.d" & abrakadabra
		$a_01_2 = {43 61 6c 6c 20 53 65 61 72 63 68 28 4d 79 46 53 4f 2e 47 65 74 46 6f 6c 64 65 72 28 61 73 64 61 29 2c 20 68 64 76 29 } //01 00  Call Search(MyFSO.GetFolder(asda), hdv)
		$a_01_3 = {43 61 6c 6c 20 62 76 78 66 63 73 64 } //00 00  Call bvxfcsd
	condition:
		any of ($a_*)
 
}