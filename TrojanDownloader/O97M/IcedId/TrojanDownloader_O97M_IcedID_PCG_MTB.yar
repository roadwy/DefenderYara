
rule TrojanDownloader_O97M_IcedID_PCG_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.PCG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1 = CreateObject("wscript.shell")
		$a_00_1 = {43 61 6c 6c 20 64 37 64 33 30 35 34 65 2e 65 78 65 63 28 66 30 61 33 36 61 34 35 29 } //1 Call d7d3054e.exec(f0a36a45)
		$a_00_2 = {63 34 31 65 36 62 63 63 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 66 61 62 36 66 38 65 35 28 } //1 c41e6bcc.Open "GET", fab6f8e5(
		$a_00_3 = {63 34 31 65 36 62 63 63 2e 53 65 6e 64 } //1 c41e6bcc.Send
		$a_00_4 = {62 33 34 32 61 66 30 63 20 3d 20 2e 72 65 73 70 6f 6e 73 65 62 6f 64 79 } //1 b342af0c = .responsebody
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}