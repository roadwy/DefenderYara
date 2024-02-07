
rule TrojanDownloader_O97M_Powdow_DD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.DD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 6f 74 69 76 65 3d 78 79 2b 79 74 2b 7a 2b 64 2b 65 2b 6c 2b 6b 2b 74 2b 78 74 65 6e 64 66 75 6e 63 74 69 6f 6e 66 75 6e 63 74 69 6f 6e 61 75 74 6f 5f 6f 70 65 6e 28 29 73 65 74 73 75 72 65 74 68 69 6e 67 73 65 61 72 63 68 3d 67 65 74 6f 62 6a 65 63 74 28 } //01 00  motive=xy+yt+z+d+e+l+k+t+xtendfunctionfunctionauto_open()setsurethingsearch=getobject(
		$a_01_1 = {3a 6d 73 67 62 6f 78 22 6d 69 63 72 6f 73 6f 66 74 6f 66 66 69 63 65 65 72 72 6f 72 22 3a 73 75 72 65 74 68 69 6e 67 73 65 61 72 63 68 2e 65 78 65 63 6d 6f 74 69 76 65 65 6e 64 66 75 6e 63 74 69 6f 6e } //01 00  :msgbox"microsoftofficeerror":surethingsearch.execmotiveendfunction
		$a_01_2 = {66 75 6e 63 74 69 6f 6e 78 79 28 29 61 73 73 74 72 69 6e 67 78 79 3d 73 75 72 65 74 68 69 6e 67 2e 6d 75 6c 74 69 2e 74 61 67 65 6e 64 66 75 6e 63 74 69 6f 6e 66 75 6e 63 74 69 6f 6e 79 74 28 29 } //00 00  functionxy()asstringxy=surething.multi.tagendfunctionfunctionyt()
	condition:
		any of ($a_*)
 
}