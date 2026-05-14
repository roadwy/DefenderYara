
rule Trojan_Win64_ChaosBot_ARA_MTB{
	meta:
		description = "Trojan:Win64/ChaosBot.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 8b 04 11 4c 33 04 08 4c 89 84 0d 00 01 00 00 48 83 c1 08 eb e4 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}