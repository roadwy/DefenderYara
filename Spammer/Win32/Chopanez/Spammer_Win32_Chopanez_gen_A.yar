
rule Spammer_Win32_Chopanez_gen_A{
	meta:
		description = "Spammer:Win32/Chopanez.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 05 00 06 00 00 "
		
	strings :
		$a_03_0 = {74 4b b8 64 00 00 00 e8 ?? ?? ff ff 83 f8 0a 7d 3c b8 1a 00 00 00 e8 ?? ?? ff ff 8b d0 83 c2 61 8d 45 ec e8 ?? ?? ff ff ff 75 f0 68 ?? ?? 40 00 ff 75 ec 68 ?? ?? 40 00 ff 75 ec } //2
		$a_03_1 = {eb 0a 68 60 ea 00 00 e8 ?? ?? ff ff 90 09 2d 00 83 3d ?? ?? 40 00 00 7e 30 33 c0 a3 ?? ?? 40 00 33 c0 a3 ?? ?? 40 00 33 c0 } //2
		$a_03_2 = {0f 87 85 00 00 00 ff 24 85 ?? 83 40 00 8b 6f 04 3b 6f 08 74 76 8d 45 1c 50 8d 4e 4c e8 ?? ?? ff ff 8b 47 08 83 c5 38 3b e8 75 ea } //4
		$a_00_3 = {26 73 65 6e 74 3d } //1 &sent=
		$a_00_4 = {26 6c 6f 73 74 3d } //1 &lost=
		$a_00_5 = {26 64 72 6f 70 3d } //1 &drop=
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*4+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}