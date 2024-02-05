
rule Trojan_Win32_ClipBanker_CAZQ_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.CAZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 08 0f be 0c 10 83 f9 90 01 01 75 2b ba 90 01 04 c1 e2 90 01 01 8b 45 08 0f be 0c 10 83 f9 90 01 01 75 17 ba 90 01 04 d1 e2 8b 45 08 0f be 0c 10 83 f9 90 01 01 75 04 b0 01 eb 90 00 } //01 00 
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00 
		$a_01_2 = {46 69 72 65 66 6f 78 4d 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}