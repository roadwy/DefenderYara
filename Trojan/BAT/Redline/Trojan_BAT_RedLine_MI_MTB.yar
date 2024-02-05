
rule Trojan_BAT_RedLine_MI_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {09 03 16 03 8e 69 28 9b 01 00 06 2a 0a 38 65 ff ff ff 0b 38 6d ff ff ff 0c 2b 92 } //05 00 
		$a_01_1 = {57 dd a2 2b 09 0f 00 00 00 d8 00 23 00 06 00 00 01 00 00 00 84 00 00 00 92 00 00 00 72 01 00 00 c6 } //01 00 
		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00 
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_RedLine_MI_MTB_2{
	meta:
		description = "Trojan:BAT/RedLine.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {57 d5 02 fc 09 0e 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 3d 00 00 00 11 00 00 00 34 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_01_3 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //01 00 
		$a_01_4 = {47 65 74 42 79 74 65 73 } //01 00 
		$a_01_5 = {73 65 74 5f 55 73 65 72 41 67 65 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}