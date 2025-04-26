
rule Backdoor_Win32_FlawedAmmyy_GA_MTB{
	meta:
		description = "Backdoor:Win32/FlawedAmmyy.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 e4 c1 e8 ?? 39 45 [0-09] 8b 04 8a [0-32] 33 [0-17] c1 85 [0-0b] 33 [0-0b] 8b 4d ?? 8b ?? ?? ?? ?? ?? ?? ?? ?? 89 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}