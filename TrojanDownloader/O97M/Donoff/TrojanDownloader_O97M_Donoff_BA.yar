
rule TrojanDownloader_O97M_Donoff_BA{
	meta:
		description = "TrojanDownloader:O97M/Donoff.BA,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {43 6f 6e 73 74 20 44 4d 43 20 3d 20 22 20 63 2f 20 64 6d 63 } //1 Const DMC = " c/ dmc
		$a_00_1 = {2e 52 75 6e 20 53 74 72 52 65 76 65 72 73 65 28 22 22 22 20 72 69 64 6b 6d 22 20 26 } //1 .Run StrReverse(""" ridkm" &
		$a_00_2 = {2e 52 75 6e 20 53 74 72 52 65 76 65 72 73 65 28 22 22 22 20 22 22 22 22 20 74 72 61 74 73 22 20 26 } //1 .Run StrReverse(""" """" trats" &
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}