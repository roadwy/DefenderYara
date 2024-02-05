
rule Trojan_BAT_Kryptik_TSR_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.TSR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {d0 51 00 00 01 28 90 01 03 0a 28 90 01 03 0a 03 6f 90 01 03 0a 17 8d 17 00 00 01 25 16 d0 01 00 00 1b 28 90 01 03 0a a2 28 90 01 03 0a 04 17 8d 10 00 00 01 25 16 02 a2 6f 90 01 03 0a 0a 2b 00 06 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}