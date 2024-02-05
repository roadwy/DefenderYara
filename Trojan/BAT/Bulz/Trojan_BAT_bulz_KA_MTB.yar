
rule Trojan_BAT_bulz_KA_MTB{
	meta:
		description = "Trojan:BAT/bulz.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {08 09 02 09 6f 19 00 00 0a 03 09 07 5d 6f 19 00 00 0a 61 d1 9d 09 17 58 0d 09 06 32 e3 } //00 00 
	condition:
		any of ($a_*)
 
}