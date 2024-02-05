
rule Trojan_BAT_Injector_SM_bit{
	meta:
		description = "Trojan:BAT/Injector.SM!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {45 00 6e 00 2d 00 69 00 6e 00 74 00 90 02 10 74 00 72 00 79 00 50 00 6f 00 90 00 } //01 00 
		$a_01_1 = {65 00 68 00 65 00 68 00 65 00 68 00 65 00 68 00 65 00 79 00 } //01 00 
		$a_01_2 = {67 61 62 62 65 72 6d 65 72 64 61 } //01 00 
		$a_03_3 = {09 11 0b 09 11 0b 91 11 90 01 01 11 0b 11 04 5d 91 61 9c 11 0b 17 d6 13 0b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}