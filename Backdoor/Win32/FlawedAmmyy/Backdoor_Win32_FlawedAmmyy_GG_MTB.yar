
rule Backdoor_Win32_FlawedAmmyy_GG_MTB{
	meta:
		description = "Backdoor:Win32/FlawedAmmyy.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c0 01 89 85 90 01 04 8b 4d bc c1 e9 90 01 01 39 8d 90 02 13 8b 0c 90 90 90 02 33 33 95 90 02 0d 2d 90 01 07 c1 85 90 01 05 8b 8d 90 01 04 33 8d 90 01 04 89 8d 90 01 04 8b 95 90 01 07 8b 8d 90 01 04 89 0c 90 90 e9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}