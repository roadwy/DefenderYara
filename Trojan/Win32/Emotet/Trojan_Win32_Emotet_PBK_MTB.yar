
rule Trojan_Win32_Emotet_PBK_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 04 0a 8b 0d 90 01 04 8b 11 8b 4d 90 01 01 0f b6 14 11 33 c2 8b 0d 90 01 04 8b 11 8b 4d 90 01 01 88 04 11 90 00 } //01 00 
		$a_02_1 = {8a 14 0a 8b 00 32 14 18 a1 90 01 04 8b 5c 24 90 01 01 8b 00 88 14 18 a1 90 01 04 40 3b c5 a3 90 01 04 0f 82 90 00 } //01 00 
		$a_81_2 = {69 67 43 61 4c 42 51 7e 6a 7b 40 6f 6a 7a 32 23 56 39 71 7c 2a 33 36 77 70 24 31 67 66 75 50 37 45 4c 71 4d 40 32 3f 6a 38 41 32 51 50 61 47 55 2a 59 52 7a 7e 5a 79 48 41 36 44 77 41 45 56 39 79 35 64 7a 6e 30 4c 50 4d 53 65 44 53 } //00 00  igCaLBQ~j{@ojz2#V9q|*36wp$1gfuP7ELqM@2?j8A2QPaGU*YRz~ZyHA6DwAEV9y5dzn0LPMSeDS
	condition:
		any of ($a_*)
 
}