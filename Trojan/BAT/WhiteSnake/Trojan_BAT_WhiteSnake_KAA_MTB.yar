
rule Trojan_BAT_WhiteSnake_KAA_MTB{
	meta:
		description = "Trojan:BAT/WhiteSnake.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 11 0a 91 11 00 11 0c 91 61 d2 9c } //00 00 
	condition:
		any of ($a_*)
 
}