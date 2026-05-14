
rule Trojan_Win64_Karstorat_AKR_MTB{
	meta:
		description = "Trojan:Win64/Karstorat.AKR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 c7 44 24 30 1d 00 00 00 48 8d 05 ?? ?? ?? ?? 48 89 44 24 28 48 89 4c 24 20 48 8d 4d ?? ?? ?? ?? ?? ?? c7 44 24 40 03 00 00 00 48 8b d3 48 8d 4d } //1
		$a_01_1 = {32 31 32 2e 32 32 37 2e 36 35 2e 31 33 32 } //2 212.227.65.132
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}