
rule Trojan_Win64_IcedID_BH_MTB{
	meta:
		description = "Trojan:Win64/IcedID.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 08 00 00 05 00 "
		
	strings :
		$a_01_0 = {43 6e 47 66 39 2e 64 6c 6c } //01 00 
		$a_01_1 = {48 31 4c 38 58 74 43 59 } //01 00 
		$a_01_2 = {4a 59 41 30 45 4a 73 51 } //01 00 
		$a_01_3 = {4b 78 45 43 48 48 35 6d 4a 35 } //01 00 
		$a_01_4 = {4e 33 4a 57 37 50 77 44 42 66 } //01 00 
		$a_01_5 = {4f 52 4f 4f 45 4c 67 } //01 00 
		$a_01_6 = {58 71 31 69 47 52 72 71 4a 54 6e } //01 00 
		$a_01_7 = {61 50 62 43 50 34 34 6d 32 61 6e } //00 00 
	condition:
		any of ($a_*)
 
}