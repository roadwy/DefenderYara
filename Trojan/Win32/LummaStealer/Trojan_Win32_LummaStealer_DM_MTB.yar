
rule Trojan_Win32_LummaStealer_DM_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.DM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 96 6e 8a 73 46 95 35 a8 33 66 2c 32 cb 59 58 58 2e ad 2c 22 cf } //10
		$a_01_1 = {89 f8 83 e0 02 89 f9 83 cf 02 0f af f8 83 f0 02 83 e1 fd 0f af c8 01 cf 83 ff 04 72 } //10
		$a_01_2 = {0f b6 d2 c1 e1 05 81 e1 e0 7f 00 00 31 d1 0f b7 94 4e 72 92 02 00 89 c7 81 e7 ff 7f 00 00 66 89 94 7e 72 92 01 00 89 da 42 66 89 84 4e 72 92 02 00 45 } //10
		$a_01_3 = {c5 0e 04 45 0b 03 56 01 0e b0 01 43 0e c0 01 02 8c 0a 0e 14 41 c3 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10) >=10
 
}