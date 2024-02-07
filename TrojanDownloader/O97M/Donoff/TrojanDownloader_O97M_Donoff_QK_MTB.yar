
rule TrojanDownloader_O97M_Donoff_QK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.QK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {22 57 73 22 20 2b 20 22 63 72 22 20 2b 20 22 69 70 74 22 20 2b 20 22 2e 53 22 } //00 00  "Ws" + "cr" + "ipt" + ".S"
	condition:
		any of ($a_*)
 
}