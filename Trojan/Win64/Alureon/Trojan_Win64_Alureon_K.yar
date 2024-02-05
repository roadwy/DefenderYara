
rule Trojan_Win64_Alureon_K{
	meta:
		description = "Trojan:Win64/Alureon.K,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 6b 69 74 36 34 5f 68 61 73 68 5f 65 6e 64 5d } //01 00 
		$a_01_1 = {5b 63 6d 64 5f 64 6c 6c 36 34 5f 68 61 73 68 5f 65 6e 64 5d } //01 00 
		$a_01_2 = {8d 42 51 48 83 c2 01 30 44 0a ff 48 81 fa 00 01 00 00 72 ec } //00 00 
	condition:
		any of ($a_*)
 
}