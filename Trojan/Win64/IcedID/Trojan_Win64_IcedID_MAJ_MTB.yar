
rule Trojan_Win64_IcedID_MAJ_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 6a 68 61 73 79 75 69 6a 6b 61 73 } //01 00 
		$a_01_1 = {42 79 41 73 64 51 } //01 00 
		$a_01_2 = {46 65 58 53 55 54 71 44 } //01 00 
		$a_01_3 = {49 35 56 57 61 56 6a 32 67 } //01 00 
		$a_01_4 = {4e 48 35 6e 4c 43 } //01 00 
		$a_01_5 = {50 43 74 6b 47 62 51 42 39 } //00 00 
	condition:
		any of ($a_*)
 
}