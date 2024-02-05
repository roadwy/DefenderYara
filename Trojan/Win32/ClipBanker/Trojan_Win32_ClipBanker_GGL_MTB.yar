
rule Trojan_Win32_ClipBanker_GGL_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.GGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 30 89 31 8b 70 04 89 71 04 8b 71 18 89 71 08 83 c0 10 83 c1 10 3b 43 08 72 e5 } //01 00 
		$a_81_1 = {73 65 6c 65 63 74 20 73 6f 75 72 63 65 2c 66 75 6e 63 74 69 6f 6e 2c 75 70 76 61 72 73 2c 6e 61 6d 65 2c 63 75 72 72 65 6e 74 6c 69 6e 65 2c 61 63 74 69 76 65 6c 69 6e 65 73 } //01 00 
		$a_81_2 = {6d 6f 67 75 2e 65 78 65 } //01 00 
		$a_81_3 = {43 6f 70 79 72 69 67 68 74 20 28 43 29 20 77 79 6f 6e 67 6b 20 32 30 32 31 } //00 00 
	condition:
		any of ($a_*)
 
}