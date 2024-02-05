
rule Trojan_BAT_QuasarRAT_MBBJ_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.MBBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 0a 06 11 06 06 91 11 0b 61 d2 9c 06 0d 09 17 58 0a 06 11 06 8e 69 32 a2 } //00 00 
	condition:
		any of ($a_*)
 
}