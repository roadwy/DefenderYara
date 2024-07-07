
rule TrojanDownloader_O97M_IcedID_PCE_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.PCE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {64 62 2e 65 78 65 63 28 61 36 39 66 35 63 31 32 29 } //1 db.exec(a69f5c12)
		$a_00_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1 CreateObject("wscript.shell")
		$a_00_2 = {63 66 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 61 61 37 64 39 33 61 64 } //1 cf.Open "GET", aa7d93ad
		$a_00_3 = {62 65 61 62 64 32 63 66 2e 53 65 6e 64 } //1 beabd2cf.Send
		$a_00_4 = {61 61 20 3d 20 2e 72 65 73 70 6f 6e 73 65 62 6f 64 79 } //1 aa = .responsebody
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}