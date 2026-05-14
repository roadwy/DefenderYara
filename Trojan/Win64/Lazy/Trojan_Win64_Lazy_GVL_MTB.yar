
rule Trojan_Win64_Lazy_GVL_MTB{
	meta:
		description = "Trojan:Win64/Lazy.GVL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 8d 40 01 f7 e9 03 d1 c1 fa 05 8b c2 c1 e8 1f 03 d0 0f be c2 6b d0 3a 0f b6 c1 ff c1 2a c2 04 34 41 30 40 ff 83 f9 1d 7c d1 } //1
		$a_01_1 = {4d 8d 40 01 f7 e1 c1 ea 04 0f be c2 6b d0 34 0f b6 c1 ff c1 2a c2 04 30 41 30 40 ff 83 f9 04 7c da } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}