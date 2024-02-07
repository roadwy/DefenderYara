
rule Trojan_BAT_Bumbulbee_NEAA_MTB{
	meta:
		description = "Trojan:BAT/Bumbulbee.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {72 01 00 00 70 28 04 00 00 06 0a 28 04 00 00 0a 06 6f 05 00 00 0a 28 06 00 00 0a 0b 07 16 07 8e 69 28 07 00 00 0a 07 0c } //05 00 
		$a_01_1 = {62 00 6f 00 74 00 61 00 6e 00 69 00 63 00 61 00 6c 00 63 00 6f 00 72 00 70 00 } //00 00  botanicalcorp
	condition:
		any of ($a_*)
 
}