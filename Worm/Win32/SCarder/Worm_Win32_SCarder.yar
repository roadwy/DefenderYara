
rule Worm_Win32_SCarder{
	meta:
		description = "Worm:Win32/SCarder,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 04 00 00 "
		
	strings :
		$a_03_0 = {c7 45 d0 00 00 00 00 c7 45 d4 0b 00 00 00 89 45 ?? c7 45 d4 15 07 00 00 89 45 ?? 83 7d ?? 05 } //1
		$a_01_1 = {8b 45 e8 8b 08 83 c1 01 8b 55 e8 89 0a 8b 45 f8 3b 45 14 } //1
		$a_01_2 = {38 2b 66 73 64 66 73 65 27 77 77 } //5 8+fsdfse'ww
		$a_01_3 = {65 32 33 34 32 32 34 32 66 6c 66 45 42 47 } //5 e2342242flfEBG
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5) >=10
 
}