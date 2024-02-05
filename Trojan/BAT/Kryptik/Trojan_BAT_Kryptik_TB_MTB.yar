
rule Trojan_BAT_Kryptik_TB_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.TB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {91 06 07 06 8e 69 6a 5d 28 90 02 04 28 90 02 04 91 61 02 07 17 6a 58 20 90 02 04 6a 5d 28 90 02 09 91 59 6a 20 90 02 04 6a 58 20 90 02 04 6a 5d d2 9c 90 01 01 07 17 6a 58 0b 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}