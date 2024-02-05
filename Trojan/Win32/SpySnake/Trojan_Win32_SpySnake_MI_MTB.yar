
rule Trojan_Win32_SpySnake_MI_MTB{
	meta:
		description = "Trojan:Win32/SpySnake.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {71 77 67 66 74 6c 6c 6d 2e 64 6c 6c } //01 00 
		$a_01_1 = {7a 6e 76 61 75 6c } //01 00 
		$a_01_2 = {54 45 4d 50 5c 6e 73 69 32 38 41 39 2e 74 6d 70 } //01 00 
		$a_01_3 = {63 72 65 61 74 69 6f 6e 5c 73 6e 61 74 63 68 5c 69 6e 74 69 6d 61 63 79 } //01 00 
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 72 65 61 63 68 65 73 5c 63 6f 62 72 61 } //00 00 
	condition:
		any of ($a_*)
 
}