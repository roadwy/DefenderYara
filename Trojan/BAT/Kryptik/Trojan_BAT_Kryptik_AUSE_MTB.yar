
rule Trojan_BAT_Kryptik_AUSE_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.AUSE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {73 4c 00 00 0a 0c 73 4d 00 00 0a 0a 08 06 28 90 01 03 0a 72 eb 2e 00 70 6f 90 01 03 0a 6f 90 01 03 0a 6f 90 01 03 0a 08 18 6f 90 01 03 0a 08 6f 90 01 03 0a 0d 02 13 04 09 11 04 16 11 04 8e b7 6f 90 01 03 0a 0b de 0f 25 28 90 01 03 0a 13 05 28 90 01 03 0a de 00 07 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}