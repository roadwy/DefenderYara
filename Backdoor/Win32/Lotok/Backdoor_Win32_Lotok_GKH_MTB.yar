
rule Backdoor_Win32_Lotok_GKH_MTB{
	meta:
		description = "Backdoor:Win32/Lotok.GKH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {b0 65 b1 74 88 44 24 ?? 88 44 24 ?? 88 44 24 ?? 88 4c 24 ?? 88 4c 24 ?? 8b 0d ?? ?? ?? ?? 8d 44 24 ?? c6 44 24 ?? 43 50 51 c6 44 24 ?? 72 c6 44 24 ?? 61 c6 44 24 ?? 45 c6 44 24 ?? 76 c6 44 24 ?? 6e c6 44 24 ?? 41 c6 44 24 ?? 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}