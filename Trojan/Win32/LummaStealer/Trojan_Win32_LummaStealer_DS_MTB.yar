
rule Trojan_Win32_LummaStealer_DS_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.DS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_03_0 = {89 f3 81 ce ?? ?? ?? ?? 0f af f7 81 f7 ?? ?? ?? ?? 81 e3 ?? ?? ?? ?? 0f af df 01 de 89 f7 21 d7 31 d6 8d 3c 7e 89 3c 88 } //10
		$a_01_1 = {8d 3c 32 21 f2 01 d2 29 d7 89 7c 24 20 8b 54 24 20 89 d6 83 f6 5b 83 e2 5b 8d 14 56 fe c2 8b 34 24 88 54 34 10 ff 04 24 } //10
		$a_03_2 = {f7 d0 8d 04 42 40 21 c8 89 44 24 20 8b 44 24 20 05 ?? ?? ?? ?? 89 c1 83 e1 01 83 f0 01 8d 04 48 88 44 1c 18 } //10
		$a_03_3 = {f7 d2 81 e7 ?? ?? ?? ?? 81 e2 ?? ?? ?? ?? 0f af d7 89 cf 81 e7 ?? ?? ?? ?? 81 c9 ?? ?? ?? ?? 0f af cf 01 d1 8d 14 08 4a 8b 0d ?? ?? ?? ?? 89 14 81 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_03_2  & 1)*10+(#a_03_3  & 1)*10) >=10
 
}