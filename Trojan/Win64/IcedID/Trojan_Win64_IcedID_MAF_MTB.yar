
rule Trojan_Win64_IcedID_MAF_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 38 52 62 52 2e 64 6c 6c } //01 00  t8RbR.dll
		$a_01_1 = {48 79 75 61 73 62 62 6a 68 61 73 } //01 00  Hyuasbbjhas
		$a_01_2 = {41 52 32 6d 67 77 70 75 } //01 00  AR2mgwpu
		$a_01_3 = {52 75 43 4d 68 6b 56 79 79 76 57 } //01 00  RuCMhkVyyvW
		$a_01_4 = {65 51 6b 4d 79 6f 66 31 76 74 6c } //01 00  eQkMyof1vtl
		$a_01_5 = {6e 37 69 4f 6c 69 7a 46 } //00 00  n7iOlizF
	condition:
		any of ($a_*)
 
}