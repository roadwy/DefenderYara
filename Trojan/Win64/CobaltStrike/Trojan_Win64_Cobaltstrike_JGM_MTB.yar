
rule Trojan_Win64_Cobaltstrike_JGM_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.JGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b ce 48 8b d7 0f 1f 44 00 00 80 31 ac 48 ff c1 48 ff ca } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}