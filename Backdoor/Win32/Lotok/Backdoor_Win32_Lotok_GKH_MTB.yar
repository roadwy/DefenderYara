
rule Backdoor_Win32_Lotok_GKH_MTB{
	meta:
		description = "Backdoor:Win32/Lotok.GKH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {b0 65 b1 74 88 44 24 90 01 01 88 44 24 90 01 01 88 44 24 90 01 01 88 4c 24 90 01 01 88 4c 24 90 01 01 8b 0d 90 01 04 8d 44 24 90 01 01 c6 44 24 90 01 01 43 50 51 c6 44 24 90 01 01 72 c6 44 24 90 01 01 61 c6 44 24 90 01 01 45 c6 44 24 90 01 01 76 c6 44 24 90 01 01 6e c6 44 24 90 01 01 41 c6 44 24 90 01 01 00 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}