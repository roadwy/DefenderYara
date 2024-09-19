
rule TrojanDownloader_O97M_Exoidovn_A{
	meta:
		description = "TrojanDownloader:O97M/Exoidovn.A,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {6c 6c 31 20 3d 20 44 61 74 65 41 64 64 28 22 64 22 2c 20 6c 31 6c 2c 20 49 49 6c 29 } //ll1 = DateAdd("d", l1l, IIl)  1
		$a_80_1 = {20 3d 20 47 65 74 4f 62 6a 65 63 74 28 22 6e 65 77 3a 6d 73 78 6d 6c 32 2e 64 6f 6d 64 6f 63 75 6d 65 6e 74 22 29 } // = GetObject("new:msxml2.domdocument")  1
		$a_80_2 = {2e 4c 6f 61 64 58 4d 4c 20 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 2e 43 61 70 74 69 6f 6e } //.LoadXML UserForm1.Label1.Caption  1
		$a_80_3 = {2e 74 72 61 6e 73 66 6f 72 6d 6e 6f 64 65 } //.transformnode  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}