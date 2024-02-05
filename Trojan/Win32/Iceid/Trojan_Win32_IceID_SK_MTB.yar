
rule Trojan_Win32_IceID_SK_MTB{
	meta:
		description = "Trojan:Win32/IceID.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5a 51 74 76 7a 50 57 55 59 6e 6f 42 52 47 } //01 00 
		$a_01_1 = {7a 45 70 6c 51 46 6d 4e 50 66 62 6f 41 74 68 4a } //01 00 
		$a_01_2 = {53 54 72 73 56 6d 76 42 54 6a 44 67 42 59 46 } //01 00 
		$a_01_3 = {75 61 73 69 66 62 79 75 67 61 73 68 66 6a 61 6b 73 68 62 61 73 73 } //00 00 
	condition:
		any of ($a_*)
 
}