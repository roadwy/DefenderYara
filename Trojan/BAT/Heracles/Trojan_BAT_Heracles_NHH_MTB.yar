
rule Trojan_BAT_Heracles_NHH_MTB{
	meta:
		description = "Trojan:BAT/Heracles.NHH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 12 17 58 13 12 11 1a 20 90 01 03 d4 5a 20 90 01 03 9f 61 38 90 01 03 ff 20 90 01 03 d5 13 0d 11 1a 20 90 01 03 80 5a 20 90 01 03 ec 61 38 90 01 03 ff 11 0e 11 05 32 08 20 90 01 03 e3 25 90 00 } //01 00 
		$a_01_1 = {73 65 72 76 65 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  server.Resources.resources
		$a_01_2 = {43 6f 6e 66 75 73 65 72 45 78 } //00 00  ConfuserEx
	condition:
		any of ($a_*)
 
}