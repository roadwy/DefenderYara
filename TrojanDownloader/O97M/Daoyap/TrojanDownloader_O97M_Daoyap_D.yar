
rule TrojanDownloader_O97M_Daoyap_D{
	meta:
		description = "TrojanDownloader:O97M/Daoyap.D,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 69 63 72 6f 73 6f 66 74 22 20 2b 20 22 2e 58 4d 4c 48 54 54 50 22 29 } //1 Microsoft" + ".XMLHTTP")
		$a_01_1 = {41 64 6f 64 62 22 20 2b 20 22 2e 53 74 72 65 61 6d 22 29 } //1 Adodb" + ".Stream")
		$a_01_2 = {53 68 65 6c 6c 22 20 2b 20 22 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 Shell" + ".Application")
		$a_01_3 = {57 53 63 72 69 70 74 22 20 2b 20 22 2e 53 68 65 6c 6c 22 29 } //1 WScript" + ".Shell")
		$a_03_4 = {52 65 70 6c 61 63 65 28 22 22 20 2b 20 22 54 22 20 2b 20 22 45 ?? ?? 4d 22 20 2b 20 22 50 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}