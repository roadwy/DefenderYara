
rule Trojan_BAT_Spy_FRM_MTB{
	meta:
		description = "Trojan:BAT/Spy.FRM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {73 15 00 00 0a 0a 00 06 1f 10 8d 1f 00 00 01 25 d0 06 00 00 04 28 90 01 03 0a 6f 90 01 03 0a 00 06 1f 10 8d 1f 00 00 01 25 d0 05 00 00 04 28 90 01 03 0a 6f 90 01 03 0a 00 06 6f 90 01 03 0a 03 16 03 8e 69 6f 90 01 03 0a 0b de 0b 06 2c 07 06 6f 90 01 03 0a 00 dc 07 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}