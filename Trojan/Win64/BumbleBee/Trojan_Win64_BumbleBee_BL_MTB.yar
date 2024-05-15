
rule Trojan_Win64_BumbleBee_BL_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 8a fc 49 01 80 90 01 04 49 8b 80 90 01 04 48 2d 90 01 04 48 31 81 90 01 04 41 8d 4f 90 01 01 41 8a 80 90 01 04 40 d2 ef 34 90 01 01 40 22 f8 49 8b 80 90 01 04 48 8b 88 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}