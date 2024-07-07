
rule TrojanDownloader_O97M_EncDoc_RVM_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.RVM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 74 72 52 65 76 65 72 73 65 28 22 74 78 74 2e 63 6e 45 2f 32 32 2f 35 34 2e 31 30 31 2e 32 33 31 2e 38 33 2f 2f 3a 70 74 74 68 22 29 } //1 StrReverse("txt.cnE/22/54.101.231.83//:ptth")
		$a_01_1 = {2e 43 72 65 61 74 65 28 44 58 43 56 4a 5a 4c 55 54 47 5a 54 48 48 55 58 4b 4c 4f 47 53 43 20 26 20 55 58 46 52 4f 59 4b 57 5a 5a 55 41 59 54 4b 41 47 47 47 46 56 57 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 70 72 6f 63 65 73 73 69 64 29 } //1 .Create(DXCVJZLUTGZTHHUXKLOGSC & UXFROYKWZZUAYTKAGGGFVW, Null, Null, processid)
		$a_01_2 = {57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 } //1 Workbook_Open()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}