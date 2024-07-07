
rule Trojan_Win64_Tedy_SMD_MTB{
	meta:
		description = "Trojan:Win64/Tedy.SMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e9 c1 fa 04 8b c2 c1 e8 90 01 01 03 d0 0f be c2 6b d0 31 0f b6 c1 ff c1 2a c2 04 39 41 30 40 ff 83 f9 04 7c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}