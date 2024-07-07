
rule Trojan_Win64_Dridex_DE_MTB{
	meta:
		description = "Trojan:Win64/Dridex.DE!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 8b 54 24 50 44 2b 54 24 50 45 01 f1 45 21 c1 44 89 54 24 50 45 89 c8 44 89 c6 44 8a 1c 37 48 8b 74 24 30 44 32 1c 0e 44 8b 44 24 50 44 89 44 24 50 4c 8b 64 24 40 45 88 1c 0c } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}