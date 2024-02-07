
rule TrojanDownloader_O97M_Donoff_CV{
	meta:
		description = "TrojanDownloader:O97M/Donoff.CV,SIGNATURE_TYPE_MACROHSTR_EXT,0d 00 0d 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {3d 20 22 4a 53 63 72 22 } //03 00  = "JScr"
		$a_01_1 = {3d 20 22 72 6f 6c 2e 53 63 22 } //02 00  = "rol.Sc"
		$a_01_2 = {29 20 26 20 41 72 72 61 79 28 22 } //02 00  ) & Array("
		$a_01_3 = {2e 41 64 64 43 6f 64 65 20 28 } //04 00  .AddCode (
		$a_01_4 = {3d 20 41 72 72 61 79 28 22 41 44 4f 44 22 2c } //00 00  = Array("ADOD",
		$a_00_5 = {5d 04 00 00 47 } //95 03 
	condition:
		any of ($a_*)
 
}