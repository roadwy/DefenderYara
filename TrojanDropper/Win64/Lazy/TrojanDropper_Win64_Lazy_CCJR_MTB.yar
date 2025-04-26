
rule TrojanDropper_Win64_Lazy_CCJR_MTB{
	meta:
		description = "TrojanDropper:Win64/Lazy.CCJR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d2 41 b8 08 02 00 00 48 8d 4d c0 e8 ?? ?? ?? ?? ba 04 01 00 00 48 8d 4d c0 ff 15 } //1
		$a_03_1 = {48 63 41 04 48 8b 4c 18 48 48 8b 01 41 b8 00 ?? da 00 48 8d 15 ?? ?? ?? ?? ff 50 48 44 8b c7 ba 04 00 00 00 48 3d 00 ?? da 00 44 0f 45 c2 44 89 84 24 90 90 00 00 00 eb } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}