
rule Trojan_Win64_UACBypassExp_PADS_MTB{
	meta:
		description = "Trojan:Win64/UACBypassExp.PADS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 1d 38 70 e0 41 f7 e8 41 03 d0 c1 fa 06 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 49 41 0f b6 c0 2a c1 04 57 41 30 01 41 ff c0 4d 8d 49 01 41 83 f8 11 7c cd } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}