
rule Backdoor_Win32_Lotok_GNP_MTB{
	meta:
		description = "Backdoor:Win32/Lotok.GNP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 c0 8a 4c 07 01 32 0c 07 89 c2 d1 ea 51 b9 ?? ?? ?? ?? 49 59 83 c0 02 60 89 f9 89 c8 61 88 0c 17 3d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Backdoor_Win32_Lotok_GNP_MTB_2{
	meta:
		description = "Backdoor:Win32/Lotok.GNP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {23 c2 83 c4 ?? a3 ?? ?? ?? ?? 8a 44 24 1c 32 c3 2a c3 32 c3 02 c3 88 04 2f 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 47 03 d1 84 c0 89 15 ?? ?? ?? ?? ?? ?? 8b 54 24 10 8b 44 24 14 83 c6 02 03 d6 3b d0 } //10
		$a_80_1 = {43 68 37 44 65 6d 64 64 6f 36 } //Ch7Demddo6  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}
rule Backdoor_Win32_Lotok_GNP_MTB_3{
	meta:
		description = "Backdoor:Win32/Lotok.GNP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 b2 72 f2 ae f7 d1 49 88 54 24 ?? 88 54 24 ?? 8b d1 bf ?? ?? ?? ?? 83 c9 ff f2 ae f7 d1 49 c6 44 24 ?? 43 c6 44 24 ?? 74 c6 44 24 ?? 54 8d 44 0a ?? c6 44 24 ?? 68 50 c6 44 24 ?? 64 c6 44 24 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}