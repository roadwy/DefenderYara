
rule Trojan_BAT_RedLine_MBAS_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MBAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 16 07 0c 08 14 72 48 40 02 70 16 8d } //01 00 
		$a_01_1 = {34 00 44 00 2d 00 35 00 41 00 2d 00 39 00 5b 00 7e 00 2d 00 5b 00 33 00 7e 00 7e 00 7e 00 2d 00 5b 00 34 00 7e 00 7e 00 7e 00 2d 00 46 00 46 00 2d 00 46 00 46 00 7e 00 7e 00 2d 00 42 00 38 00 7e } //01 00 
		$a_01_2 = {4c 4c 4c 4c 35 36 } //00 00  LLLL56
	condition:
		any of ($a_*)
 
}