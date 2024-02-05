
rule Trojan_BAT_SkarCrypt_A_MTB{
	meta:
		description = "Trojan:BAT/SkarCrypt.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {09 08 11 04 6f 90 01 01 00 00 0a 1f 30 59 6c 23 00 00 00 00 00 00 10 40 1a 11 04 59 17 59 6c 28 90 01 01 00 00 0a 5a d2 58 d2 0d 11 04 17 59 13 04 90 00 } //02 00 
		$a_03_1 = {06 02 11 05 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 11 04 11 05 09 5d 91 1f 30 59 59 d1 6f 90 01 01 00 00 0a 26 11 05 17 58 13 05 11 05 02 6f 90 01 01 00 00 0a 09 59 17 59 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}