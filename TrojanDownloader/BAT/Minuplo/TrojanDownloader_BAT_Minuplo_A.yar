
rule TrojanDownloader_BAT_Minuplo_A{
	meta:
		description = "TrojanDownloader:BAT/Minuplo.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 72 6f 6a 65 63 74 73 5c 4d 69 6e 69 55 70 6c 6f 61 64 2e 6e 65 74 5c 41 70 70 73 } //01 00  Projects\MiniUpload.net\Apps
		$a_01_1 = {70 00 72 00 65 00 6d 00 69 00 75 00 6d 00 68 00 65 00 73 00 61 00 70 00 6c 00 61 00 72 00 69 00 6d 00 2e 00 6e 00 65 00 74 00 } //01 00  premiumhesaplarim.net
		$a_01_2 = {6c 00 61 00 6c 00 61 00 6b 00 65 00 72 00 31 00 2e 00 6e 00 65 00 74 00 } //01 00  lalaker1.net
		$a_01_3 = {2f 00 6d 00 61 00 72 00 6b 00 65 00 74 00 2e 00 70 00 68 00 70 00 3f 00 74 00 3d 00 } //01 00  /market.php?t=
		$a_01_4 = {70 00 61 00 67 00 65 00 73 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 2f 00 3f 00 72 00 65 00 66 00 5f 00 74 00 79 00 70 00 65 00 3d 00 72 00 65 00 67 00 69 00 73 00 74 00 72 00 61 00 74 00 69 00 6f 00 6e 00 5f 00 66 00 6f 00 72 00 6d 00 } //01 00  pages/create/?ref_type=registration_form
		$a_01_5 = {52 65 6b 6c 61 6d 5c 55 70 64 61 74 65 32 30 31 33 5c 6f 62 6a } //01 00  Reklam\Update2013\obj
		$a_01_6 = {6d 00 69 00 6e 00 69 00 75 00 70 00 6c 00 6f 00 61 00 64 00 2e 00 6e 00 65 00 74 00 2f 00 69 00 72 00 2f 00 73 00 32 00 2e 00 70 00 68 00 70 00 } //00 00  miniupload.net/ir/s2.php
	condition:
		any of ($a_*)
 
}