
rule TrojanDownloader_O97M_IcedID_PCH_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.PCH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //01 00  = CreateObject("wscript.shell")
		$a_00_1 = {43 61 6c 6c 20 63 64 64 61 35 66 64 61 2e 65 78 65 63 28 65 36 66 64 35 31 31 63 29 } //01 00  Call cdda5fda.exec(e6fd511c)
		$a_00_2 = {61 66 39 32 62 63 66 30 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 66 31 32 65 63 31 37 30 } //01 00  af92bcf0.Open "GET", f12ec170
		$a_00_3 = {61 66 39 32 62 63 66 30 2e 53 65 6e 64 } //01 00  af92bcf0.Send
		$a_00_4 = {63 65 64 66 65 37 33 62 20 3d 20 2e 72 65 73 70 6f 6e 73 65 62 6f 64 79 } //00 00  cedfe73b = .responsebody
	condition:
		any of ($a_*)
 
}