
rule Worm_Win32_Kzerab_A{
	meta:
		description = "Worm:Win32/Kzerab.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {e8 00 00 00 00 58 89 45 e0 8d 45 dc 50 68 ?? ?? ?? ?? 68 01 00 00 80 ff 15 ?? ?? ?? ?? 85 c0 74 07 33 c0 e9 } //1
		$a_01_1 = {81 7d f4 f5 7a 00 00 73 39 c7 45 d0 00 00 00 00 eb 09 8b 55 d0 83 c2 01 89 55 d0 83 7d d0 04 73 1f } //2
		$a_01_2 = {81 7d fc 09 0a 00 00 73 3b c7 45 f8 00 00 00 00 eb 09 8b 4d f8 83 c1 01 89 4d f8 83 7d f8 04 73 21 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=2
 
}