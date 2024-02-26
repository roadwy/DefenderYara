
rule Trojan_BAT_AveMariaRAT_S_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRAT.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 06 72 13 14 00 70 6f 90 01 04 0b 16 0c 2b 13 00 07 08 07 08 91 20 90 01 04 59 d2 9c 08 17 58 0c 00 08 07 8e 69 fe 04 0d 09 2d e3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}