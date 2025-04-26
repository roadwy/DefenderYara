
rule TrojanDownloader_O97M_Emotet_KK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.KK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {69 55 6f 67 66 54 4c 20 3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 5a 63 4a 79 6a 4c 2c 20 69 48 72 7a 44 47 46 77 2c 20 50 6d 29 } //1 iUogfTL = CallByName(ZcJyjL, iHrzDGFw, Pm)
		$a_01_1 = {46 6c 73 72 7a 5a 20 3d 20 4d 69 64 28 4e 48 6f 61 47 2c 20 70 73 62 47 6e 4e 4f 28 64 58 45 76 4e 78 29 2c 20 47 6e 66 58 69 29 } //1 FlsrzZ = Mid(NHoaG, psbGnNO(dXEvNx), GnfXi)
		$a_01_2 = {46 6f 72 20 45 61 63 68 20 51 4f 51 57 54 4e 4a 20 49 6e 20 54 57 4c 42 2e 49 74 65 6d 73 } //1 For Each QOQWTNJ In TWLB.Items
		$a_01_3 = {61 6a 6d 20 3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2c 20 56 41 55 52 66 46 65 6b 2c 20 44 44 63 29 } //1 ajm = CallByName(ActiveDocument, VAURfFek, DDc)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}