
rule Trojan_BAT_Exnet_AAIC_MTB{
	meta:
		description = "Trojan:BAT/Exnet.AAIC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {0a 02 8e 69 8d 2f 00 00 01 0b 16 0c 2b 15 00 07 08 02 08 91 06 08 06 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 02 8e 69 fe 04 0d 09 2d e1 } //01 00 
		$a_01_1 = {42 6f 73 73 42 6f 74 6e 65 74 2e 43 6c 69 65 6e 74 } //01 00 
		$a_01_2 = {73 71 6c 73 72 76 73 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}