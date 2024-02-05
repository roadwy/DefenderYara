
rule Trojan_Win32_Azorult_MA_MTB{
	meta:
		description = "Trojan:Win32/Azorult.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 8b 15 b4 38 45 00 52 8b 45 f4 50 8b 0d 4c 2b 45 00 ff d1 8b 55 f4 52 a1 50 2b 45 00 ff d0 b9 01 00 00 00 6b d1 00 03 15 b4 38 45 00 89 15 bc 39 45 00 a1 bc 39 45 00 0f b7 08 81 f9 4d 5a 00 00 74 24 } //01 00 
		$a_00_1 = {0f af c3 fe c8 0f ba e0 10 0f ad d8 3c 50 0f ba e0 a8 8a c6 3a c6 86 e0 48 3a c6 0f ac d8 d0 } //01 00 
		$a_01_2 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //01 00 
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}