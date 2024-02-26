
rule Trojan_BAT_GhostStealer_MB_MTB{
	meta:
		description = "Trojan:BAT/GhostStealer.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {13 0b 08 28 90 01 03 0a 2d 10 08 11 0b 28 90 01 03 0a 16 13 18 dd 1e 03 00 00 11 13 7b 2c 00 00 04 11 0b 6f 90 01 03 0a 26 14 13 0c 72 d7 06 00 70 73 c0 00 00 0a 13 0d 11 07 13 0e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}