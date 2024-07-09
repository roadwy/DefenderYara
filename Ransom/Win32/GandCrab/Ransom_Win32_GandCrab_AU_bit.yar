
rule Ransom_Win32_GandCrab_AU_bit{
	meta:
		description = "Ransom:Win32/GandCrab.AU!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {ba 01 00 00 00 6b c2 06 c6 80 ?? ?? ?? ?? 33 b9 01 00 00 00 6b d1 07 c6 82 ?? ?? ?? ?? 32 b8 01 00 00 00 c1 e0 03 c6 80 ?? ?? ?? ?? 2e b9 01 00 00 00 6b d1 09 c6 82 ?? ?? ?? ?? 64 b8 01 00 00 00 6b c8 0a c6 81 ?? ?? ?? ?? 6c ba 01 00 00 00 6b c2 0b c6 80 ?? ?? ?? ?? 6c b9 01 00 00 00 6b d1 0c c6 82 ?? ?? ?? ?? 00 } //2
		$a_03_1 = {33 ca 8b 45 ?? c1 e8 05 03 45 ?? 33 c8 8b 55 ?? 2b d1 89 55 ?? 8b 45 ?? c1 e0 04 03 45 ?? 8b 4d ?? 03 4d ?? 33 c1 8b 55 ?? c1 ea 05 03 55 ?? 33 c2 8b 4d ?? 2b c8 89 4d } //2
		$a_01_2 = {03 45 f0 8b 4d cc 03 4d f0 8a 91 32 09 00 00 88 10 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=4
 
}