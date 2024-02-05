
rule Trojan_BAT_RedlineStealer_PSJB_MTB{
	meta:
		description = "Trojan:BAT/RedlineStealer.PSJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {28 22 26 00 06 0b 07 1f 20 8d 25 00 00 01 25 d0 36 14 00 04 28 90 01 03 0a 6f 90 01 03 0a 07 1f 10 8d 25 00 00 01 25 d0 37 14 00 04 28 90 01 03 0a 6f 90 01 03 0a 06 07 6f 90 01 03 0a 17 73 90 01 03 0a 0c 08 02 16 02 8e 69 6f ce 00 00 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}