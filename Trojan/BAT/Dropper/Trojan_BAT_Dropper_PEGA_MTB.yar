
rule Trojan_BAT_Dropper_PEGA_MTB{
	meta:
		description = "Trojan:BAT/Dropper.PEGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {72 87 00 00 70 28 90 01 03 0a 0a 28 90 01 03 0a 06 28 90 01 03 0a 39 d7 00 00 00 06 28 90 01 03 0a 3a 81 00 00 00 28 90 01 03 0a 06 28 90 01 03 0a 7e 36 00 00 0a 72 a1 00 00 70 17 6f 90 01 03 0a 0b 07 72 fd 00 00 70 72 21 01 00 70 06 72 21 01 00 70 28 90 01 03 0a 6f 90 01 03 0a 06 28 90 01 03 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}