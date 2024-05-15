
rule Trojan_BAT_Barys_MAAA_MTB{
	meta:
		description = "Trojan:BAT/Barys.MAAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 8d 25 00 00 01 13 05 16 13 07 11 0e 20 82 bd 8c b3 5a 20 51 53 e2 48 61 38 73 fe ff ff 11 05 16 11 04 11 07 11 06 28 90 01 01 00 00 06 11 07 11 06 58 13 07 90 00 } //02 00 
		$a_03_1 = {ff ff 12 09 28 90 01 01 00 00 0a 74 01 00 00 1b 13 0a 11 0e 20 53 92 17 fb 5a 20 b3 03 3e 75 61 38 b9 fd ff ff 11 04 11 08 28 90 01 01 00 00 06 13 09 11 0e 20 fc 26 0e 21 5a 20 75 e9 a0 d3 61 38 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}