
rule Trojan_Win32_Pikabot_RB_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {82 30 f5 3e 82 30 4b 3d ?? ?? ?? ?? 82 28 ef 3e 82 40 2d 3d 82 38 56 3e 82 40 2d 3e 82 58 14 3d 82 80 ?? ?? ?? ?? bd 3e 82 30 4b } //1
		$a_01_1 = {66 c1 c0 0f f8 51 66 05 18 4b f5 a8 f0 66 85 ca 60 66 31 c3 } //1
		$a_01_2 = {34 01 80 d3 2f f6 d0 fe cb d2 db fe c3 9c 2c bf d2 eb 53 f8 34 c9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}