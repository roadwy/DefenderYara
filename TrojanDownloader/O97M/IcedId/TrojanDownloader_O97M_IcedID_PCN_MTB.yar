
rule TrojanDownloader_O97M_IcedID_PCN_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.PCN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //01 00  CreateObject("wscript.shell")
		$a_00_1 = {2e 65 78 65 63 20 28 65 34 35 36 66 63 31 30 29 } //01 00  .exec (e456fc10)
		$a_00_2 = {3d 20 53 70 6c 69 74 28 64 37 36 63 61 62 30 32 2c 20 22 7c 22 29 } //01 00  = Split(d76cab02, "|")
		$a_00_3 = {3d 20 53 74 72 43 6f 6e 76 28 65 63 36 63 37 35 66 38 2c 20 76 62 55 6e 69 63 6f 64 65 29 } //01 00  = StrConv(ec6c75f8, vbUnicode)
		$a_00_4 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c } //01 00  .Open "GET",
		$a_00_5 = {2e 64 38 63 62 39 39 39 33 20 65 65 36 61 66 66 30 61 28 30 29 20 2b 20 22 20 22 20 2b 20 66 61 33 31 65 31 31 36 } //00 00  .d8cb9993 ee6aff0a(0) + " " + fa31e116
	condition:
		any of ($a_*)
 
}