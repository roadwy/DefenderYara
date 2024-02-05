
rule Trojan_BAT_Kryptik_PALLV_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.PALLV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {2b 02 26 16 02 6f 90 01 03 0a d4 8d 25 00 00 01 0a 02 06 16 06 8e 69 6f 90 01 03 0a 26 06 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}