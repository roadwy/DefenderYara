
rule Backdoor_Win32_Bladabindi_GG_MTB{
	meta:
		description = "Backdoor:Win32/Bladabindi.GG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {59 98 22 a8 82 b8 21 1d 63 bb 96 50 12 00 24 c8 e2 29 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}