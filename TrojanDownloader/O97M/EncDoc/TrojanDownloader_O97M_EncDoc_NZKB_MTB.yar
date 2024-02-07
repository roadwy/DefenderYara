
rule TrojanDownloader_O97M_EncDoc_NZKB_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.NZKB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 52 75 6e 28 49 58 4e 36 61 79 4d 59 35 52 6a 4d 49 44 35 2c 20 6a 55 44 58 77 58 5f 50 79 77 5f 71 72 4f 6a 5f 29 } //01 00  .Run(IXN6ayMY5RjMID5, jUDXwX_Pyw_qrOj_)
		$a_01_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 49 43 4f 6c 50 49 5f 77 58 62 6f 69 47 35 41 35 29 } //01 00  = CreateObject(ICOlPI_wXboiG5A5)
		$a_01_2 = {3d 20 22 66 64 73 66 67 66 64 20 20 68 67 66 64 66 68 67 20 20 68 67 66 67 6a 66 20 66 73 64 20 64 66 61 73 66 65 77 22 } //00 00  = "fdsfgfd  hgfdfhg  hgfgjf fsd dfasfew"
	condition:
		any of ($a_*)
 
}