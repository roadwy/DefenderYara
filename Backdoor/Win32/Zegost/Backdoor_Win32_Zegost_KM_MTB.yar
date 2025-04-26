
rule Backdoor_Win32_Zegost_KM_MTB{
	meta:
		description = "Backdoor:Win32/Zegost.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f be 04 1e 99 bd db 06 00 00 f7 fd b8 cd cc cc cc 83 c6 01 80 c2 4b 30 14 39 f7 e1 c1 ea 02 8d 04 92 8b d1 2b d0 75 ?? 33 f6 83 c1 01 3b 4c 24 ?? 7c } //1
		$a_02_1 = {0f be 04 1e 99 bd d9 06 00 00 f7 fd 8a 04 39 bd 05 00 00 00 80 c2 4f 32 c2 46 88 04 39 8b c1 99 f7 fd 85 d2 75 ?? 33 f6 8b 44 24 ?? 41 3b c8 7c } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}