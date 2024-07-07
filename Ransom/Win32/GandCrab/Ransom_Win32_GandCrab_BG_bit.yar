
rule Ransom_Win32_GandCrab_BG_bit{
	meta:
		description = "Ransom:Win32/GandCrab.BG!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 8b 00 8b 4d f8 03 c1 8a 08 88 4d 90 01 01 8a 48 90 01 01 88 4d 90 01 01 8a 48 90 01 01 0f b6 40 90 01 01 50 8d 45 90 01 01 50 8d 45 90 01 01 50 8d 45 90 01 01 50 88 4d 90 01 01 e8 90 01 04 8a 45 90 01 01 83 45 f8 90 01 01 88 04 3e 8a 45 90 01 01 83 c4 90 01 01 46 88 04 3e 8a 45 90 01 01 46 88 04 3e 8b 45 f8 46 3b 03 72 ac 90 00 } //1
		$a_03_1 = {8b 4d 08 8b c1 c1 e0 90 01 01 89 45 f8 8b 45 0c 01 45 f8 8b c1 c1 e8 90 01 01 89 45 fc 8b 45 14 01 45 fc 8b 45 10 03 c1 33 45 fc 33 45 f8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}