
rule Backdoor_Win64_BazarLoader_STB{
	meta:
		description = "Backdoor:Win64/BazarLoader.STB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 64 31 2e 64 6c 6c 00 53 74 61 72 74 46 75 6e 63 00 } //01 00 
		$a_01_1 = {77 73 32 5f 33 32 64 6c 6c 00 6e 74 64 6c 6c 2e 64 6c 6c 00 73 68 65 6c 6c 33 32 2e 64 6c 6c 00 77 69 6e 69 6e 65 74 2e 64 6c 6c 00 75 72 6c 6d 6f 6e 2e 64 6c 6c } //01 00 
		$a_01_2 = {48 8b 00 48 b9 00 00 00 00 ff ff ff ff 48 8b 40 30 48 23 c1 48 89 90 01 03 48 8b 90 01 03 8b 40 08 48 0b 90 00 } //00 00 
		$a_00_3 = {7e 15 } //00 00 
	condition:
		any of ($a_*)
 
}