
rule Trojan_Win64_Luca_ALU_MTB{
	meta:
		description = "Trojan:Win64/Luca.ALU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 0f b6 44 0a 02 41 c1 e0 10 44 0f b7 0c 0a 45 01 c8 41 81 c0 90 01 04 44 33 04 10 44 89 44 15 b0 48 83 c2 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}