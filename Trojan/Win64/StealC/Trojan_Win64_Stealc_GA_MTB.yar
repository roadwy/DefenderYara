
rule Trojan_Win64_Stealc_GA_MTB{
	meta:
		description = "Trojan:Win64/Stealc.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b7 c8 81 e9 19 04 00 00 74 14 83 e9 09 74 0f 83 e9 01 74 0a 83 e9 1c 74 05 83 f9 04 75 08 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}