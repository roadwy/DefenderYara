
rule TrojanDownloader_O97M_IcedID_PCL_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.PCL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {3d 20 53 70 6c 69 74 28 61 66 36 37 37 36 38 38 2c 20 22 7c 22 29 } //1 = Split(af677688, "|")
		$a_00_1 = {64 66 65 37 39 62 64 37 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1 dfe79bd7 = CreateObject("wscript.shell")
		$a_00_2 = {64 66 65 37 39 62 64 37 2e 65 78 65 63 28 63 62 33 63 62 65 35 33 29 } //1 dfe79bd7.exec(cb3cbe53)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}