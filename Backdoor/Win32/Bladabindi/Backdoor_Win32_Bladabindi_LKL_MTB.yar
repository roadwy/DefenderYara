
rule Backdoor_Win32_Bladabindi_LKL_MTB{
	meta:
		description = "Backdoor:Win32/Bladabindi.LKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 eb 02 83 e9 04 8b 45 0c 8b 55 10 81 e0 ff 00 00 00 33 d2 8b 04 85 58 d1 63 00 89 01 8b 45 0c 8b 55 10 0f ac d0 08 c1 ea 08 89 45 0c 89 55 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}