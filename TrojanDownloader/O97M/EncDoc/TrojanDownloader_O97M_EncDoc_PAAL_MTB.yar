
rule TrojanDownloader_O97M_EncDoc_PAAL_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAAL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {76 62 5f 6e 61 6d 65 3d 22 7a 6a 75 7a 6e 22 61 74 74 72 69 } //1 vb_name="zjuzn"attri
		$a_01_1 = {66 75 6e 63 74 69 6f 6e 79 79 7a 7a 7a 28 65 65 65 65 77 61 73 73 74 72 69 6e 67 29 64 69 6d 6c 66 65 68 28 29 61 73 76 61 72 69 61 6e 74 72 65 64 69 6d 6c 66 65 68 28 34 29 6c 66 65 68 28 30 29 3d 63 68 72 28 38 30 29 2b 72 61 6e 67 65 28 22 61 37 22 29 2e 68 79 70 65 72 6c 69 6e 6b 73 28 31 29 2e 6e 61 6d } //1 functionyyzzz(eeeewasstring)dimlfeh()asvariantredimlfeh(4)lfeh(0)=chr(80)+range("a7").hyperlinks(1).nam
		$a_01_2 = {33 29 2c 6c 66 65 68 28 34 29 29 65 6e 64 66 75 6e 63 74 69 6f 6e 66 75 6e 63 74 69 6f 6e 6b 6c 73 61 64 28 29 61 73 6f 62 6a 65 63 74 73 65 74 6b 6c 73 61 64 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 6d 6f 6e 64 61 79 2e 63 6f 6e } //1 3),lfeh(4))endfunctionfunctionklsad()asobjectsetklsad=createobject(monday.con
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}