
rule TrojanDownloader_O97M_Donoff_FSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.FSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {22 63 22 20 26 20 53 74 72 52 65 76 65 72 73 65 28 22 22 22 20 22 22 22 22 20 74 72 61 74 73 22 20 26 20 22 20 63 22 20 26 20 48 55 69 75 38 32 37 54 59 52 48 29 20 26 20 65 77 61 6c 6c 4c 49 73 70 5f 33 52 20 26 20 22 22 22 22 2c 20 30 2c 20 46 61 6c 73 65 } //1 "c" & StrReverse(""" """" trats" & " c" & HUiu827TYRH) & ewallLIsp_3R & """", 0, False
		$a_01_1 = {22 63 22 20 26 20 53 74 72 52 65 76 65 72 73 65 28 4b 4d 4b 4d 20 26 20 43 43 43 43 20 26 20 48 55 69 75 38 32 37 54 59 52 48 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 22 72 69 64 22 29 20 26 20 22 20 22 22 22 20 26 20 4d 69 64 28 65 77 61 6c 6c 4c 49 73 70 5f 33 52 2c 20 31 2c 20 4c 65 6e 28 65 77 61 6c 6c 4c 49 73 70 5f 33 52 29 20 2d } //1 "c" & StrReverse(KMKM & CCCC & HUiu827TYRH) & StrReverse("rid") & " """ & Mid(ewallLIsp_3R, 1, Len(ewallLIsp_3R) -
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}