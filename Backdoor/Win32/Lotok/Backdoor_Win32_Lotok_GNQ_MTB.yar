
rule Backdoor_Win32_Lotok_GNQ_MTB{
	meta:
		description = "Backdoor:Win32/Lotok.GNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 c3 2a c3 32 c3 89 2d ?? ?? ?? ?? 8b 2d ?? ?? ?? ?? 02 c3 88 04 17 03 e9 83 c4 ?? 47 89 0d ?? ?? ?? ?? 89 2d ?? ?? ?? ?? 84 c0 ?? ?? 8b 44 24 ?? 83 c6 ?? 03 c6 3b 44 24 ?? 0f 8c } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Backdoor_Win32_Lotok_GNQ_MTB_2{
	meta:
		description = "Backdoor:Win32/Lotok.GNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {b1 72 50 53 c6 44 24 ?? 56 c6 44 24 ?? 69 88 4c 24 ?? c6 44 24 ?? 75 c6 44 24 ?? 61 c6 44 24 ?? 6c c6 44 24 ?? 50 88 4c 24 ?? c6 44 24 ?? 6f c6 44 24 ?? 65 c6 44 24 ?? 63 c6 44 24 ?? 00 ff d7 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}