
rule TrojanDownloader_O97M_IcedID_PCF_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.PCF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {64 33 2e 65 78 65 63 28 62 31 65 35 66 35 64 66 29 } //1 d3.exec(b1e5f5df)
		$a_00_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1 = CreateObject("wscript.shell")
		$a_00_2 = {3d 20 2e 72 65 73 70 6f 6e 73 65 62 6f 64 79 } //1 = .responsebody
		$a_00_3 = {32 34 30 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 66 31 64 62 62 62 35 66 } //1 240.Open "GET", f1dbbb5f
		$a_00_4 = {63 65 65 36 30 32 34 30 2e 53 65 6e 64 } //1 cee60240.Send
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}