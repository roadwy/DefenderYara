
rule TrojanDownloader_O97M_EncDoc_PAAT_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAAT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 5f 6f 70 65 6e 28 29 6d 73 67 62 6f 78 5f 73 74 72 72 65 76 65 72 73 65 28 73 72 65 76 65 72 73 65 6d 6f 64 28 22 63 65 66 69 6f 66 6c 61 6c 73 74 69 6e 65 2d 72 72 21 72 6f 65 72 22 29 29 63 6f 6d 70 75 74 65 72 6f 6f 31 3d 73 74 72 72 65 76 65 72 73 65 28 73 72 65 76 65 72 73 65 6d 6f 64 28 22 } //01 00  o_open()msgbox_strreverse(sreversemod("cefioflalstine-rr!roer"))computeroo1=strreverse(sreversemod("
		$a_01_1 = {65 28 73 74 72 72 65 76 65 72 73 65 28 73 72 65 76 65 72 73 65 6d 6f 64 28 73 72 65 76 65 72 73 65 6d 6f 64 28 73 72 65 76 65 72 73 65 6d 6f 64 28 22 3a 22 29 29 29 29 29 29 29 73 65 74 5f 68 6f 74 65 6c 5f 3d 5f 67 65 74 6f 62 6a 65 63 74 5f 28 62 65 61 63 68 29 68 6f 74 65 6c } //01 00  e(strreverse(sreversemod(sreversemod(sreversemod(":")))))))set_hotel_=_getobject_(beach)hotel
		$a_01_2 = {66 6c 78 36 39 38 77 68 73 29 73 74 65 70 32 73 72 65 76 65 72 73 65 6d 6f 64 3d 73 72 65 76 65 72 73 65 6d 6f 64 26 73 74 72 72 65 76 65 72 73 65 28 6d 69 64 28 66 6c 78 36 39 38 77 68 73 2c 61 63 73 36 35 73 61 71 66 2c 32 29 29 64 6f 65 76 65 6e 74 73 6e 65 78 74 } //00 00  flx698whs)step2sreversemod=sreversemod&strreverse(mid(flx698whs,acs65saqf,2))doeventsnext
	condition:
		any of ($a_*)
 
}