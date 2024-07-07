
rule Backdoor_Win32_FlawedAmmyy_GA_MTB{
	meta:
		description = "Backdoor:Win32/FlawedAmmyy.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 e4 c1 e8 90 01 01 39 45 90 02 09 8b 04 8a 90 02 32 33 90 02 17 c1 85 90 02 0b 33 90 02 0b 8b 4d 90 01 01 8b 90 01 08 89 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}