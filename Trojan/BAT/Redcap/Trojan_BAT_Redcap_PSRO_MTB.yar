
rule Trojan_BAT_Redcap_PSRO_MTB{
	meta:
		description = "Trojan:BAT/Redcap.PSRO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {28 19 00 00 0a 2c 23 72 87 00 00 70 72 99 00 00 70 73 15 00 00 0a 25 17 6f 16 00 00 0a 25 16 6f 17 00 00 0a 28 18 00 00 0a 26 20 00 20 00 00 0b 72 a9 00 00 70 23 00 00 00 00 00 00 00 40 0c 72 ab 00 00 70 28 1a 00 00 0a 26 1f 1a 28 1b 00 00 0a } //00 00 
	condition:
		any of ($a_*)
 
}