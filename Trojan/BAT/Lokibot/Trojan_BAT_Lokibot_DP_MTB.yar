
rule Trojan_BAT_Lokibot_DP_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.DP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {2f 2f 34 35 2e 31 33 33 2e 31 2e 38 34 2f 67 61 74 74 79 2f 6d 75 70 64 61 74 65 2e 70 6e 67 } //01 00  //45.133.1.84/gatty/mupdate.png
		$a_81_1 = {47 77 72 78 79 64 6b 75 6b 66 67 62 } //01 00  Gwrxydkukfgb
		$a_81_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_81_3 = {41 6e 69 6d 61 6c } //01 00  Animal
		$a_81_4 = {53 6c 65 65 70 } //00 00  Sleep
	condition:
		any of ($a_*)
 
}