
rule Backdoor_Win32_Poison_K{
	meta:
		description = "Backdoor:Win32/Poison.K,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 40 8b cb 99 f7 f9 0f b6 04 3a 03 45 f8 89 55 08 8d 34 3a 99 f7 f9 89 55 f8 8d 04 3a 50 56 89 45 f4 e8 ba 00 00 00 8b 45 0c 8b 55 f4 59 0f b6 12 59 8b 4d fc 03 c8 0f b6 06 03 c2 8b f3 99 f7 fe 8a 04 3a 30 01 ff 45 fc 8b 45 fc 3b 45 10 7c ad } //1
		$a_03_1 = {33 c0 8a 14 30 30 14 01 40 83 f8 10 7c f4 83 c1 10 4f 75 ec ff 15 90 01 04 8d 4b f0 85 c9 76 12 8b 44 24 18 2b e8 8a 14 28 80 f2 90 01 01 88 10 40 49 75 f4 5f 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}