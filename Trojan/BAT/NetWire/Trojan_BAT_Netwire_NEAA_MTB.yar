
rule Trojan_BAT_Netwire_NEAA_MTB{
	meta:
		description = "Trojan:BAT/Netwire.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {26 26 26 2b 36 2b 37 dd 5b 00 00 00 0b 15 2c f3 2b e4 28 2f 00 00 0a 2b ea 28 30 00 00 0a 2b c7 28 0e 00 00 06 2b c7 6f 31 00 00 0a 2b c2 28 32 00 00 0a 2b bd 07 2b c0 } //01 00 
		$a_01_1 = {53 6d 61 72 74 41 73 73 65 6d 62 6c 79 2e 41 74 74 72 69 62 75 74 65 73 } //01 00 
		$a_01_2 = {49 6e 76 6f 6b 65 } //00 00 
	condition:
		any of ($a_*)
 
}