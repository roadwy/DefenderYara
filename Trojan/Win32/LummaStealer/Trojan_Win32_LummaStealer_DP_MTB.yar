
rule Trojan_Win32_LummaStealer_DP_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.DP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_03_0 = {89 c7 09 d7 21 c2 81 f6 ?? ?? ?? ?? 09 d6 8d 14 36 f7 d2 01 f2 21 fa 89 54 24 1c 8b 54 24 1c 80 c2 66 88 94 04 } //10
		$a_01_1 = {89 fb f7 d3 01 d3 29 d7 89 da 31 fa 21 ca 31 fa 09 cb 21 d3 89 5c 24 18 8b 4c 24 18 80 c1 5c 88 8c 04 } //10
		$a_01_2 = {89 ce 09 d6 89 c7 21 d7 f7 d7 f7 d6 01 d6 21 fe 89 74 24 0c 8b 54 24 0c 80 c2 18 88 54 04 d0 } //10
		$a_03_3 = {89 ca 81 e2 ?? ?? ?? ?? 89 ce 81 e6 ?? ?? ?? ?? 81 c9 ?? ?? ?? ?? 0f af ce 81 f6 ?? ?? ?? ?? 0f af f2 01 f1 8d 14 08 4a 8b 0d ?? ?? ?? ?? 89 14 81 } //10
		$a_03_4 = {89 fe 83 e6 01 f7 de 21 de 83 cf 02 0f af fd 01 ca 29 fa 01 f2 69 ca ?? ?? ?? ?? 01 c1 49 8b 15 ?? ?? ?? ?? 89 0c 82 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_03_3  & 1)*10+(#a_03_4  & 1)*10) >=10
 
}