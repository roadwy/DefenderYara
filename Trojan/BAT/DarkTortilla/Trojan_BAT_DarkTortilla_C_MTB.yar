
rule Trojan_BAT_DarkTortilla_C_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {0d 08 17 8d 90 01 01 00 00 01 25 16 09 28 90 01 01 00 00 0a 9d 6f 90 00 } //02 00 
		$a_01_1 = {00 00 0a b4 9c 11 07 17 d6 13 07 11 07 11 06 31 d5 } //01 00 
		$a_01_2 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //00 00  HttpWebRequest
	condition:
		any of ($a_*)
 
}