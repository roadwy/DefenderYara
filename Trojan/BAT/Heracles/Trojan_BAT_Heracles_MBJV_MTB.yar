
rule Trojan_BAT_Heracles_MBJV_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MBJV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 d5 a2 fd 09 0f 00 00 00 fa 25 33 00 16 00 00 02 } //01 00 
		$a_01_1 = {24 37 32 30 62 62 64 61 36 2d 62 32 62 38 2d 34 38 36 34 2d 39 37 33 66 2d 39 35 36 32 66 66 66 61 34 38 31 62 } //01 00  $720bbda6-b2b8-4864-973f-9562fffa481b
		$a_01_2 = {54 77 6f 5f 44 69 63 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //00 00  Two_Dice.Properties.Resources.resource
	condition:
		any of ($a_*)
 
}