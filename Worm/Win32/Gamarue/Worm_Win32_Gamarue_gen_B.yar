
rule Worm_Win32_Gamarue_gen_B{
	meta:
		description = "Worm:Win32/Gamarue.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {3d 07 fd e5 4c 0f 84 ?? ?? 00 00 3d 6c 32 81 81 0f 84 ?? ?? 00 00 3d af 33 e2 31 0f 84 ?? ?? 00 00 3d f6 7d d4 91 0f 84 ?? ?? 00 00 3d 54 dc cd e8 0f 84 ?? ?? 00 00 3d 6c 6d 8c 00 0f 84 ?? ?? 00 00 3d 0e ba d0 a8 0f 84 ?? ?? 00 00 3d 0e 3c ef a4 0f 84 ?? ?? 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Worm_Win32_Gamarue_gen_B_2{
	meta:
		description = "Worm:Win32/Gamarue.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {3d 32 44 dd 99 0f 84 ?? ?? 00 00 3d b4 9d 85 2d 0f 84 ?? ?? 00 00 3d ce 0d 34 64 0f 84 ?? ?? 00 00 3d 74 44 c5 63 0f 84 ?? ?? 00 00 3d 8b 9c 9c 34 0f 84 ?? ?? 00 00 3d ce eb 46 34 0f 84 ?? ?? 00 00 3d fe b1 a9 5b 0f 84 ?? ?? 00 00 3d f3 be e2 3c 0f 84 ?? ?? 00 00 3d 2b f0 46 3d 0f 84 ?? ?? 00 00 3d f7 10 ae 77 0f 84 ?? ?? 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}