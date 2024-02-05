
rule Trojan_BAT_Nanocore_COER_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.COER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {7e 11 00 00 04 73 be 00 00 0a 72 ad 03 00 70 6f 90 01 03 0a 74 0f 00 00 1b 0a 06 28 90 01 03 06 0b 07 72 dd 03 00 70 28 90 01 03 06 74 4d 00 00 01 6f 90 01 03 0a 1a 9a 80 10 00 00 04 23 d1 37 b7 3b 43 62 20 40 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}