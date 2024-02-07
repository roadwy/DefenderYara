
rule TrojanDownloader_BAT_Seraph_RI_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {58 00 6d 00 75 00 62 00 62 00 64 00 63 00 7a 00 62 00 6d 00 62 00 73 00 70 00 6a 00 75 00 } //01 00  Xmubbdczbmbspju
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6a 00 75 00 73 00 74 00 6e 00 6f 00 72 00 6d 00 61 00 6c 00 73 00 69 00 74 00 65 00 2e 00 64 00 64 00 6e 00 73 00 2e 00 6e 00 65 00 74 00 } //01 00  http://justnormalsite.ddns.net
		$a_01_2 = {24 34 36 38 34 37 30 37 38 2d 66 63 64 61 2d 34 66 65 61 2d 62 33 33 38 2d 34 65 65 34 35 37 38 62 37 61 35 39 } //00 00  $46847078-fcda-4fea-b338-4ee4578b7a59
	condition:
		any of ($a_*)
 
}