
rule Backdoor_Win32_Remcos_GZZ_MTB{
	meta:
		description = "Backdoor:Win32/Remcos.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d8 33 fa 89 5c 24 ?? 8b cf 8b 74 24 ?? 8b df 8b c6 c1 eb 0f 0f a4 c1 11 33 d2 89 7c 24 ?? c1 e0 ?? 0b d1 0b d8 } //10
		$a_03_1 = {f0 64 a1 30 00 00 00 89 78 ?? 8b 42 ?? 03 c7 ff d0 } //5
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*5) >=15
 
}