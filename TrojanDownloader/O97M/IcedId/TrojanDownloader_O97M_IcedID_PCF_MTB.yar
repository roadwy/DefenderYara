
rule TrojanDownloader_O97M_IcedID_PCF_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.PCF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {64 33 2e 65 78 65 63 28 62 31 65 35 66 35 64 66 29 } //01 00  d3.exec(b1e5f5df)
		$a_00_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //01 00  = CreateObject("wscript.shell")
		$a_00_2 = {3d 20 2e 72 65 73 70 6f 6e 73 65 62 6f 64 79 } //01 00  = .responsebody
		$a_00_3 = {32 34 30 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 66 31 64 62 62 62 35 66 } //01 00  240.Open "GET", f1dbbb5f
		$a_00_4 = {63 65 65 36 30 32 34 30 2e 53 65 6e 64 } //00 00  cee60240.Send
	condition:
		any of ($a_*)
 
}