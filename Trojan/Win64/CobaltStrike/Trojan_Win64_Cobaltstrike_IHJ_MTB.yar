
rule Trojan_Win64_Cobaltstrike_IHJ_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.IHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 2b c1 48 8b 4c 24 38 0f b6 04 01 8b 4c 24 04 33 c8 8b c1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}