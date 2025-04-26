
rule Trojan_Win64_Convagent_SPGE_MTB{
	meta:
		description = "Trojan:Win64/Convagent.SPGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 8b c9 33 c9 8b d1 8b c1 4d 8b c1 66 41 83 38 5c 0f 44 c2 66 41 39 08 74 08 ff c2 49 83 c0 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}