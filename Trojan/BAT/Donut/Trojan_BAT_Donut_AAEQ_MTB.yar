
rule Trojan_BAT_Donut_AAEQ_MTB{
	meta:
		description = "Trojan:BAT/Donut.AAEQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {69 17 59 2b 3b 2b 2e 2b 3a 50 2b 3a 91 16 2c 39 26 2b 39 50 2b 39 2b 3a 50 07 91 9c 02 50 07 08 9c 06 16 2d d2 17 25 2c 0e 58 17 2c 02 0a 07 15 2c db 17 59 0b 06 07 32 ce 2a } //00 00 
	condition:
		any of ($a_*)
 
}