
rule Ransom_Win64_Magniber_PC_MTB{
	meta:
		description = "Ransom:Win64/Magniber.PC!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 86 37 03 00 00 e9 79 ff ff ff } //01 00 
		$a_01_1 = {32 86 0b 03 00 00 e9 87 00 00 00 } //01 00 
		$a_01_2 = {32 c2 eb 86 } //01 00 
		$a_01_3 = {8a d0 eb 4c } //01 00 
		$a_01_4 = {88 07 eb eb } //01 00 
		$a_01_5 = {48 ff c6 eb 70 } //01 00 
		$a_01_6 = {48 ff c7 e9 f6 fe ff ff } //01 00 
		$a_01_7 = {48 ff c1 e9 cf 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}