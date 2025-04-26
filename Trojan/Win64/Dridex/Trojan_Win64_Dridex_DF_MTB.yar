
rule Trojan_Win64_Dridex_DF_MTB{
	meta:
		description = "Trojan:Win64/Dridex.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 04 24 48 8b 4c 24 28 48 81 c1 81 c5 dd a6 48 8b 54 24 18 44 8a 04 02 4c 8b 4c 24 08 45 88 04 01 66 44 8b 54 24 26 66 41 81 f2 93 a2 66 44 89 54 24 26 48 01 c8 48 8b 4c 24 10 48 39 c8 48 89 04 24 74 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}