
rule Trojan_Win64_Convagent_ARAX_MTB{
	meta:
		description = "Trojan:Win64/Convagent.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 e9 c1 fa 04 8b c2 c1 e8 1f 03 d0 0f be c2 6b d0 36 0f b6 c1 2a c2 04 38 41 30 00 ff c1 4d 8d 40 01 83 f9 0f 7c d4 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}