
rule Trojan_Win64_Convagent_CCJT_MTB{
	meta:
		description = "Trojan:Win64/Convagent.CCJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c2 41 2a c0 f6 d0 41 fe c0 48 ff c1 30 41 ff 44 3a c2 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}