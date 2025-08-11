
rule Trojan_Win64_LummaStealer_YAK_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.YAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {3d ab 30 f1 93 0f 8e ?? ?? ?? ?? 3d 66 bd 2d 9a 0f 8e ?? ?? ?? ?? 3d 67 bd 2d 9a } //1
		$a_01_1 = {0f af c8 f6 c1 01 b8 25 f4 dd 44 b9 29 b0 01 38 } //1
		$a_01_2 = {48 8b 4d b8 0f b6 04 01 48 63 4d f0 48 8b 55 90 30 04 0a 8b 5d f0 83 c3 01 } //10
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*10) >=12
 
}