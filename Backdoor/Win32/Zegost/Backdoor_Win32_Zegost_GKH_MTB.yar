
rule Backdoor_Win32_Zegost_GKH_MTB{
	meta:
		description = "Backdoor:Win32/Zegost.GKH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c2 8b f0 33 c9 85 f6 90 01 02 8d a4 24 90 01 04 b8 90 01 04 f7 e1 8b c2 d1 e8 b2 03 f6 ea 8a d1 2a d0 80 c2 02 00 91 90 01 04 41 3b ce 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}