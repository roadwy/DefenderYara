
rule Trojan_BAT_RedLine_EH_MTB{
	meta:
		description = "Trojan:BAT/RedLine.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 06 00 "
		
	strings :
		$a_01_0 = {07 09 18 6f 93 00 00 0a 1f 10 28 94 00 00 0a 13 06 08 17 8d 67 00 00 01 25 16 11 06 9c 6f 95 00 00 0a 00 09 18 58 0d 00 09 07 6f 96 00 00 0a fe 04 13 07 11 07 2d c8 } //00 00 
	condition:
		any of ($a_*)
 
}