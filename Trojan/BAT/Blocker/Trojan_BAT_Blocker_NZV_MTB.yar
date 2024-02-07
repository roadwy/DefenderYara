
rule Trojan_BAT_Blocker_NZV_MTB{
	meta:
		description = "Trojan:BAT/Blocker.NZV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 16 73 90 01 01 00 00 0a 73 90 01 01 00 00 0a 0c 08 07 6f 90 01 01 00 00 0a 07 6f 90 01 01 00 00 0a 0d de 90 00 } //01 00 
		$a_01_1 = {79 00 51 00 4f 00 68 00 71 00 6f 00 53 00 30 00 68 00 79 00 } //01 00  yQOhqoS0hy
		$a_81_2 = {78 48 66 33 58 38 77 6d 70 2e 76 50 } //00 00  xHf3X8wmp.vP
	condition:
		any of ($a_*)
 
}