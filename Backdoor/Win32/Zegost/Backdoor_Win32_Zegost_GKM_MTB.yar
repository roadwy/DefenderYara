
rule Backdoor_Win32_Zegost_GKM_MTB{
	meta:
		description = "Backdoor:Win32/Zegost.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 f6 0f be 04 3e 99 f7 fd 8b 44 24 90 01 01 83 c6 01 80 c2 4b 30 91 90 01 04 8d 94 08 90 01 04 b8 cd cc cc cc f7 e2 c1 ea 02 8d 04 92 8b d1 2b d0 83 c2 02 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}