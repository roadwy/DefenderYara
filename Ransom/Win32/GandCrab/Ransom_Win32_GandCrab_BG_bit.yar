
rule Ransom_Win32_GandCrab_BG_bit{
	meta:
		description = "Ransom:Win32/GandCrab.BG!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 8b 00 8b 4d f8 03 c1 8a 08 88 4d ?? 8a 48 ?? 88 4d ?? 8a 48 ?? 0f b6 40 ?? 50 8d 45 ?? 50 8d 45 ?? 50 8d 45 ?? 50 88 4d ?? e8 ?? ?? ?? ?? 8a 45 ?? 83 45 f8 ?? 88 04 3e 8a 45 ?? 83 c4 ?? 46 88 04 3e 8a 45 ?? 46 88 04 3e 8b 45 f8 46 3b 03 72 ac } //1
		$a_03_1 = {8b 4d 08 8b c1 c1 e0 ?? 89 45 f8 8b 45 0c 01 45 f8 8b c1 c1 e8 ?? 89 45 fc 8b 45 14 01 45 fc 8b 45 10 03 c1 33 45 fc 33 45 f8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}