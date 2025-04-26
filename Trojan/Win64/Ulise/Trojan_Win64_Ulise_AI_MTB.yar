
rule Trojan_Win64_Ulise_AI_MTB{
	meta:
		description = "Trojan:Win64/Ulise.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b ca 41 f7 e3 80 c1 ?? 43 30 0c 02 c1 ea 03 8d 0c 92 03 c9 44 3b d9 4d 0f 44 cd 41 ff c3 49 ff c2 44 3b de 7c } //2
		$a_01_1 = {f7 e9 03 d1 c1 fa 08 8b c2 c1 e8 1f 03 d0 b8 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}