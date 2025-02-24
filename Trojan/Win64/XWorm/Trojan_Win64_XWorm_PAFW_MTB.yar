
rule Trojan_Win64_XWorm_PAFW_MTB{
	meta:
		description = "Trojan:Win64/XWorm.PAFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 0f 72 e1 04 66 0f 6f c1 66 0f 72 d0 1f 66 0f fe c1 66 0f 38 40 c5 66 0f fa d0 66 0f 6e c2 0f 54 d6 66 0f 67 d2 66 0f 67 d2 66 0f fc d0 66 0f 6e 41 f8 0f 57 d0 66 0f 7e 51 f8 41 83 f8 28 0f 8c } //2
		$a_01_1 = {41 f7 e8 c1 fa 04 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 36 41 0f b6 c0 41 ff c0 2a c1 04 35 41 30 41 ff 41 83 f8 2c 7c } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}