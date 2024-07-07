
rule Trojan_Win32_TurtleLoader_R_dha{
	meta:
		description = "Trojan:Win32/TurtleLoader.R!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {20 0f 10 40 e0 83 c1 40 8d 40 40 66 0f f8 c1 66 0f ef c1 66 0f fc c1 0f 11 40 a0 0f 10 40 b0 66 0f f8 c1 66 0f ef c1 66 0f fc c1 0f } //1
		$a_01_1 = {11 40 b0 0f 10 40 c0 66 0f f8 c1 66 0f ef c1 66 0f fc c1 0f 11 40 c0 0f 10 40 d0 66 0f f8 c1 66 0f ef c1 66 0f fc c1 0f 11 40 d0 } //1
		$a_01_2 = {8a 04 31 2c 2a 34 2a 04 2a 88 04 31 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}