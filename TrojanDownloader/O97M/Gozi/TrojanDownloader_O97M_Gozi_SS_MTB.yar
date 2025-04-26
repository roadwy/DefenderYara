
rule TrojanDownloader_O97M_Gozi_SS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Gozi.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 76 73 50 68 64 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 6c 47 4b 4c 48 28 33 29 20 26 20 22 2e 22 20 26 20 6c 47 4b 4c 48 28 33 29 20 26 20 22 72 65 71 75 65 73 74 2e 35 2e 31 22 29 } //1 Set vsPhd = CreateObject(lGKLH(3) & "." & lGKLH(3) & "request.5.1")
		$a_01_1 = {43 7a 6c 6e 50 20 3d 20 53 70 6c 69 74 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 31 23 29 2e 54 69 74 6c 65 2c 20 6a 72 49 55 4e 29 } //1 CzlnP = Split(ActiveDocument.Shapes(1#).Title, jrIUN)
		$a_01_2 = {68 45 4f 70 6f 20 3d 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 47 73 58 56 4d 2e 70 64 66 } //1 hEOpo = "c:\programdata\GsXVM.pdf
		$a_01_3 = {53 65 74 20 6c 72 52 69 46 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 6b 74 61 52 6b 29 } //1 Set lrRiF = CreateObject(ktaRk)
		$a_01_4 = {76 73 50 68 64 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 5a 72 61 55 71 28 48 55 74 6c 79 29 } //1 vsPhd.Open "GET", ZraUq(HUtly)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}