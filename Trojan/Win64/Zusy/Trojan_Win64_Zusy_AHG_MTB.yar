
rule Trojan_Win64_Zusy_AHG_MTB{
	meta:
		description = "Trojan:Win64/Zusy.AHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_00_0 = {0f b6 b4 18 ea 01 00 00 40 c0 ee 04 40 0f b6 f6 48 8d 3d b9 66 05 00 0f b6 34 37 48 81 fa 0b 02 00 00 0f 83 } //3
		$a_03_1 = {48 89 c1 48 b8 89 ?? ?? ?? ?? ?? ?? ?? 48 89 d6 48 f7 ea 48 01 f2 48 c1 fa 03 48 c1 fe 3f 48 29 f2 48 ff c2 48 89 c8 48 89 d1 } //2
		$a_03_2 = {48 89 c6 48 b8 89 ?? ?? ?? ?? ?? ?? ?? 49 89 d0 48 f7 ef 4c 8d 0c 3a 49 c1 f9 03 48 c1 ff 3f 49 29 f9 49 8d 79 01 48 89 f0 4c 89 c2 48 89 fe } //2
	condition:
		((#a_00_0  & 1)*3+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=5
 
}