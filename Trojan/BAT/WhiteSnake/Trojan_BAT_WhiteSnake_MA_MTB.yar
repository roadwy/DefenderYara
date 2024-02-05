
rule Trojan_BAT_WhiteSnake_MA_MTB{
	meta:
		description = "Trojan:BAT/WhiteSnake.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 ad 11 ae 11 ac 11 ae 94 11 ac 11 ae 94 59 9e 00 11 ae 17 58 13 ae 11 ae 11 ac 8e 69 fe 04 13 af 11 af 3a d7 ff ff ff } //01 00 
		$a_01_1 = {57 bf a2 3d 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 9c } //01 00 
		$a_01_2 = {38 32 32 37 34 32 31 30 2d 36 33 66 62 2d 34 34 34 34 2d 39 38 33 39 2d 39 32 37 35 61 34 66 62 39 34 38 34 } //01 00 
		$a_01_3 = {5f 62 76 54 33 75 63 6b 68 4c 78 31 30 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}