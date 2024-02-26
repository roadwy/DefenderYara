
rule Trojan_BAT_Injuke_ARA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 04 11 05 09 11 05 09 8e 69 5d 91 07 11 05 91 61 d2 9c 11 05 17 58 13 05 11 05 07 8e 69 32 e0 } //01 00 
		$a_01_1 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //01 00  HttpWebRequest
		$a_01_2 = {57 65 62 52 65 73 70 6f 6e 73 65 } //00 00  WebResponse
	condition:
		any of ($a_*)
 
}