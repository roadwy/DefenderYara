
rule Backdoor_Win64_Coroxy_ZD_MTB{
	meta:
		description = "Backdoor:Win64/Coroxy.ZD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 8b 45 ?? 31 18 83 45 ?? ?? 83 45 ?? ?? 8b 45 ?? 3b 45 ?? 72 90 0a 50 00 8b 45 ?? 8b 55 ?? 01 02 6a 00 e8 ?? ?? ?? ?? 8b 5d ?? 03 5d ?? 03 5d ?? 2b d8 6a 00 e8 ?? ?? ?? ?? 2b d8 6a 00 e8 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}