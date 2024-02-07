
rule TrojanDownloader_O97M_Donoff_A_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.A!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 61 6c 65 78 64 65 70 61 73 65 2e 63 6f 61 63 68 2f 77 70 2d 61 64 6d 69 6e 2f 49 63 34 5a 56 73 68 2f 40 68 74 74 70 3a 2f 2f 61 6d 69 72 61 6c 2e 67 61 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 63 55 46 54 7a 65 35 2f } //01 00  https://alexdepase.coach/wp-admin/Ic4ZVsh/@http://amiral.ga/wp-content/cUFTze5/
		$a_01_1 = {2b 20 22 2e 65 78 65 22 } //00 00  + ".exe"
	condition:
		any of ($a_*)
 
}