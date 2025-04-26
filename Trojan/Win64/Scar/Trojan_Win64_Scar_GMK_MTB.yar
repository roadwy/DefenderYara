
rule Trojan_Win64_Scar_GMK_MTB{
	meta:
		description = "Trojan:Win64/Scar.GMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 89 f1 4c 89 4c 24 58 e8 ?? ?? ?? ?? 31 d2 41 ba 3e 00 00 00 44 89 f9 89 c0 41 ff c7 4c 8b 4c 24 58 49 f7 f2 44 39 7c 24 48 66 0f be 44 15 00 66 41 89 04 4c } //10
		$a_80_1 = {47 6c 6f 62 61 6c 5c 4d 25 6c 6c 75 } //Global\M%llu  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}