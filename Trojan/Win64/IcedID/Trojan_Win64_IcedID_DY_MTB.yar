
rule Trojan_Win64_IcedID_DY_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {41 4c 74 4b 67 31 47 4e 47 47 6d 41 32 4e } //01 00 
		$a_01_1 = {45 48 35 45 77 4c 6a 43 64 51 31 70 78 4d 59 79 } //01 00 
		$a_01_2 = {49 6e 33 54 78 71 36 6c 56 59 73 4b 72 64 6a 33 53 66 32 } //01 00 
		$a_01_3 = {4b 4c 36 69 33 46 41 50 48 38 33 56 63 58 } //01 00 
		$a_01_4 = {4c 52 79 62 45 38 4d 30 47 4f 59 49 45 68 4d 78 50 66 36 70 39 } //00 00 
	condition:
		any of ($a_*)
 
}