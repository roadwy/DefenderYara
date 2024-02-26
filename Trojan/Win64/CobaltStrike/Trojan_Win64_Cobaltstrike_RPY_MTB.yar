
rule Trojan_Win64_Cobaltstrike_RPY_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 d2 c7 44 24 20 40 00 00 00 41 b9 00 30 00 00 41 b8 00 02 04 00 48 8b cb ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Cobaltstrike_RPY_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 8b 0d 3b 10 00 00 ba 05 00 00 00 80 34 3e 05 ff 15 24 10 00 00 48 ff c6 48 81 fe 7b 03 00 00 72 c0 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Cobaltstrike_RPY_MTB_3{
	meta:
		description = "Trojan:Win64/Cobaltstrike.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 c7 84 24 20 03 00 00 00 00 00 00 c7 84 24 28 03 00 00 00 00 00 00 48 8d 84 24 28 03 00 00 48 89 44 24 28 c7 44 24 20 00 00 00 00 31 c9 31 d2 49 89 d8 45 31 c9 e8 d2 ad 03 00 } //01 00 
		$a_01_1 = {48 8b b4 24 a0 00 00 00 4c 8b bc 24 a8 00 00 00 48 8b bc 24 b0 00 00 00 31 c9 48 89 fa 41 b8 00 30 00 00 41 b9 40 00 00 00 e8 cf ac 03 00 } //00 00 
	condition:
		any of ($a_*)
 
}