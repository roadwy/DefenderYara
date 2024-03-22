
rule Trojan_BAT_Crysan_SP_MTB{
	meta:
		description = "Trojan:BAT/Crysan.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {28 07 00 00 06 0b 07 8e 69 20 00 04 00 00 2e f0 } //00 00 
	condition:
		any of ($a_*)
 
}