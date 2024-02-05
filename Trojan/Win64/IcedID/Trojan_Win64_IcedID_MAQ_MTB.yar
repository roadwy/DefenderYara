
rule Trojan_Win64_IcedID_MAQ_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 6d 45 49 2e 64 6c 6c } //01 00 
		$a_01_1 = {63 66 68 64 73 68 66 64 67 6a 68 64 67 64 66 68 78 } //01 00 
		$a_01_2 = {4f 4c 4d 79 53 6f 42 48 45 52 48 41 59 } //01 00 
		$a_01_3 = {56 51 67 53 41 47 6b 52 54 67 } //01 00 
		$a_01_4 = {64 67 47 45 56 4d 45 79 55 51 77 41 } //01 00 
		$a_01_5 = {69 54 62 66 43 4d 61 5a 44 65 56 51 63 } //00 00 
	condition:
		any of ($a_*)
 
}