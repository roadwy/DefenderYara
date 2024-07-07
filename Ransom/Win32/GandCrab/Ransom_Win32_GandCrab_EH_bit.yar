
rule Ransom_Win32_GandCrab_EH_bit{
	meta:
		description = "Ransom:Win32/GandCrab.EH!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {eb 09 c1 c0 07 0f be c9 33 c1 42 8a 0a 84 c9 75 f1 } //1
		$a_03_1 = {33 c9 8b c1 80 b0 08 90 01 04 40 3b c7 72 f4 90 00 } //1
		$a_03_2 = {8d 43 01 0f b6 d8 8a 94 1d 90 01 04 0f b6 c2 03 c6 0f b6 f0 8a 84 35 90 01 04 88 84 1d 90 01 04 88 94 35 90 01 04 0f b6 8c 1d 90 01 04 0f b6 c2 03 c8 8b 45 14 0f b6 c9 8a 8c 0d 90 01 04 30 08 40 89 45 14 83 ef 01 75 b1 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}