
rule TrojanDownloader_O97M_IcedID_RVA_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.RVA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 50 67 72 6f 68 2e 70 64 66 } //1 c:\programdata\Pgroh.pdf
		$a_00_1 = {53 70 6c 69 74 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 31 23 29 2e 54 69 74 6c 65 2c 20 6f 62 64 56 73 29 } //1 Split(ActiveDocument.Shapes(1#).Title, obdVs)
		$a_00_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 61 53 73 68 54 28 33 29 20 26 20 22 2e 22 20 26 20 61 53 73 68 54 28 33 29 20 26 20 22 72 65 71 75 65 73 74 2e 35 2e 31 22 29 } //1 CreateObject(aSshT(3) & "." & aSshT(3) & "request.5.1")
		$a_00_3 = {4f 70 65 6e 20 22 47 45 54 22 2c 20 76 76 78 44 59 28 53 69 53 70 5a 29 2c 20 46 61 6c 73 65 } //1 Open "GET", vvxDY(SiSpZ), False
		$a_00_4 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 41 44 4f 44 42 2e 53 74 72 65 61 6d 22 29 } //1 CreateObject("ADODB.Stream")
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}