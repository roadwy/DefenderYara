
rule TrojanDownloader_O97M_Donoff_PDB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.PDB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 22 68 74 74 70 73 3a 2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 2f 76 6d 66 61 76 74 6c 75 22 29 29 61 64 69 61 67 2e 73 61 76 65 74 6f 66 69 6c 65 22 62 66 76 62 79 2e 76 62 73 22 2c 32 27 73 61 76 65 62 69 6e 61 72 79 64 61 74 61 74 6f 64 69 73 6b 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 72 75 6e 22 62 66 76 62 79 2e 76 62 73 22 2c 30 2c 66 61 6c 73 65 73 65 74 61 64 69 61 67 3d 6e 6f 74 68 69 6e 67 65 6e 64 73 75 62 } //1 ("https://pastebin.com/raw/vmfavtlu"))adiag.savetofile"bfvby.vbs",2'savebinarydatatodiskcreateobject("wscript.shell").run"bfvby.vbs",0,falsesetadiag=nothingendsub
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_PDB_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.PDB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 65 62 75 67 2e 50 72 69 6e 74 20 4d 73 67 42 6f 78 28 22 45 52 52 4f 52 21 22 2c 20 76 62 4f 4b 43 61 6e 63 65 6c 29 3b 20 72 65 74 75 72 6e 73 3b 20 31 } //1 Debug.Print MsgBox("ERROR!", vbOKCancel); returns; 1
		$a_01_1 = {6f 62 6a 2e 55 67 61 6e 64 61 } //1 obj.Uganda
		$a_01_2 = {6d 61 6e 70 6f 77 65 72 68 6f 72 73 65 20 3d 20 73 61 6c 75 31 20 2b 20 73 61 6c 75 32 20 2b 20 73 61 6c 75 33 20 2b 20 73 61 6c 75 34 } //1 manpowerhorse = salu1 + salu2 + salu3 + salu4
		$a_01_3 = {73 61 6c 75 62 68 61 69 20 3d 20 6d 61 6e 70 6f 77 65 72 68 6f 72 73 65 } //1 salubhai = manpowerhorse
		$a_01_4 = {44 65 62 75 67 2e 41 73 73 65 72 74 20 28 53 68 65 6c 6c 28 73 61 6c 75 62 68 61 69 29 29 } //1 Debug.Assert (Shell(salubhai))
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}