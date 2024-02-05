
rule Trojan_Win64_IcedID_DO_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {68 37 45 33 79 2e 64 6c 6c } //01 00 
		$a_01_1 = {77 65 79 75 68 69 61 64 73 6a 6d 6b 61 6a 75 69 } //01 00 
		$a_01_2 = {43 6f 44 6f 73 44 61 74 65 54 69 6d 65 54 6f 46 69 6c 65 54 69 6d 65 } //01 00 
		$a_01_3 = {52 61 73 44 65 6c 65 74 65 45 6e 74 72 79 41 } //01 00 
		$a_01_4 = {42 69 6e 64 4d 6f 6e 69 6b 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}