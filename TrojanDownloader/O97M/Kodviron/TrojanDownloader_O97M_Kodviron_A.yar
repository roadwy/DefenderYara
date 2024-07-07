
rule TrojanDownloader_O97M_Kodviron_A{
	meta:
		description = "TrojanDownloader:O97M/Kodviron.A,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 } //1 Sub Auto_Open()
		$a_00_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 53 58 4d 4c 32 2e 58 4d 4c 48 54 54 50 22 29 } //1 = CreateObject("MSXML2.XMLHTTP")
		$a_00_2 = {43 68 72 57 28 31 30 34 29 20 26 20 43 68 72 57 28 31 31 36 29 20 26 20 43 68 72 57 28 31 31 36 29 20 26 20 43 68 72 57 28 31 31 32 29 20 26 20 43 68 72 57 28 35 38 29 20 26 20 43 68 72 57 28 34 37 29 20 26 20 43 68 72 57 28 34 37 29 20 26 } //1 ChrW(104) & ChrW(116) & ChrW(116) & ChrW(112) & ChrW(58) & ChrW(47) & ChrW(47) &
		$a_00_3 = {29 2c 20 45 6e 76 69 72 6f 6e 28 43 68 72 57 28 } //1 ), Environ(ChrW(
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}