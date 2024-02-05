
rule Trojan_Win32_Tinba_GZN_MTB{
	meta:
		description = "Trojan:Win32/Tinba.GZN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 44 24 1c 8b 0d 90 01 04 03 c0 2b 44 24 90 01 01 2b 44 24 90 01 01 03 c1 03 44 24 10 01 44 24 2c a1 90 01 04 3b 05 90 01 04 7d 3b 8b 4c 24 10 41 0f af 4c 24 34 03 4c 24 3c c1 f8 90 01 01 51 8b 0d 0c 4f 43 00 90 00 } //01 00 
		$a_01_1 = {47 65 74 53 79 73 74 65 6d 49 6e 66 6f } //01 00 
		$a_01_2 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}