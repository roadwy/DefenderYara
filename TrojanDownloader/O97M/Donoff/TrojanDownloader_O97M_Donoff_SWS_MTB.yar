
rule TrojanDownloader_O97M_Donoff_SWS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SWS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 31 39 32 2e 32 31 30 2e 31 34 39 2e 32 34 32 2f 6d 61 63 2e 74 78 74 22 } //1 ://192.210.149.242/mac.txt"
		$a_01_1 = {3d 20 46 56 76 51 64 57 2e 45 78 65 63 28 77 70 6c 6d 57 28 29 29 } //1 = FVvQdW.Exec(wplmW())
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}