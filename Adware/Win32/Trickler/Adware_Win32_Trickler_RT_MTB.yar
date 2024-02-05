
rule Adware_Win32_Trickler_RT_MTB{
	meta:
		description = "Adware:Win32/Trickler.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {b9 00 08 00 00 8d 54 24 60 2b c8 8b 44 24 5c 52 83 c1 fe 50 51 56 } //0a 00 
		$a_01_1 = {8d 54 01 01 52 e8 b1 f8 00 00 8b f0 83 c4 04 85 f6 74 6b 55 53 c6 06 } //01 00 
		$a_01_2 = {43 53 70 75 64 44 65 6c 65 74 65 } //01 00 
		$a_01_3 = {47 65 74 47 61 74 6f 72 } //01 00 
		$a_01_4 = {74 72 69 63 6b 6c 65 72 2e 69 6e 66 } //01 00 
		$a_01_5 = {73 6f 66 74 77 61 72 65 5c 51 77 65 72 74 79 75 69 6f 5c 54 72 69 63 6b 6c 65 72 5c 53 65 73 73 69 6f 6e 73 } //00 00 
	condition:
		any of ($a_*)
 
}