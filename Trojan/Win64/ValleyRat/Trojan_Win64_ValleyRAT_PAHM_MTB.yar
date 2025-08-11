
rule Trojan_Win64_ValleyRAT_PAHM_MTB{
	meta:
		description = "Trojan:Win64/ValleyRAT.PAHM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8d 4c 24 40 ?? ?? 48 8b 44 24 40 48 2b 44 24 30 0f 57 c9 f2 48 0f 2a c8 0f 57 c0 f2 48 0f 2a 44 24 38 f2 0f 5e c8 66 0f 2f f1 } //2
		$a_03_1 = {48 8b 44 24 48 48 2b 44 24 30 0f 57 c9 f2 48 0f 2a c8 0f 57 c0 f2 48 0f 2a 44 24 38 f2 0f 5e c8 f2 ?? ?? ?? ?? ?? ?? ?? f2 0f 2c c1 3d 88 13 00 00 7e } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}