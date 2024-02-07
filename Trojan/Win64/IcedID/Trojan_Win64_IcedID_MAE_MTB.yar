
rule Trojan_Win64_IcedID_MAE_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 54 39 39 63 4a 4e 30 7a } //01 00  vT99cJN0z
		$a_01_1 = {48 79 75 61 73 62 62 6a 68 61 73 } //01 00  Hyuasbbjhas
		$a_01_2 = {41 73 63 48 7a 42 73 78 75 69 47 } //01 00  AscHzBsxuiG
		$a_01_3 = {44 4a 68 44 41 53 6b 44 34 55 } //01 00  DJhDASkD4U
		$a_01_4 = {45 35 4c 4d 6d 41 64 66 6e 36 } //01 00  E5LMmAdfn6
		$a_01_5 = {4a 47 49 44 68 36 36 46 5a 6b 6f } //00 00  JGIDh66FZko
	condition:
		any of ($a_*)
 
}