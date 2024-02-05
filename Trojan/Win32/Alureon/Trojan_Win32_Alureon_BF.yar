
rule Trojan_Win32_Alureon_BF{
	meta:
		description = "Trojan:Win32/Alureon.BF,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 45 54 5f 50 41 52 41 4d 53 } //01 00 
		$a_01_1 = {5b 72 65 66 65 72 65 72 5f 65 6e 64 5d 00 } //01 00 
		$a_01_2 = {5b 6a 73 5f 69 6e 6a 65 63 74 5f 65 6e 64 5d 00 } //01 00 
		$a_01_3 = {5b 50 41 4e 45 4c 5f 53 49 47 4e 5f 43 48 45 43 4b 5d 00 } //01 00 
		$a_01_4 = {4e 65 74 46 69 6c 74 65 72 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}