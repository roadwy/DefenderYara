
rule Trojan_Win64_Dridex_ARA_MTB{
	meta:
		description = "Trojan:Win64/Dridex.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 18 48 8b 4c 24 10 8a 14 01 4c 8b 04 24 41 88 14 00 48 83 c0 01 48 89 44 24 18 4c 8b 4c 24 08 4c 39 c8 75 d8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}