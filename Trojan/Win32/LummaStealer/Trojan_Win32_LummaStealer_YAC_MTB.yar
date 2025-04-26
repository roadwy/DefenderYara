
rule Trojan_Win32_LummaStealer_YAC_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {5f 50 81 e0 ?? ?? ?? ?? 81 e8 ?? ?? ?? ?? 81 f0 ?? ?? ?? ?? 58 0f b6 8d } //10
		$a_03_1 = {58 0f b6 8d ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 0f be 02 2b c1 8b 8d ?? ?? ?? ?? 88 01 eb } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}
rule Trojan_Win32_LummaStealer_YAC_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 9c c0 8b 04 85 ?? ?? ?? ?? b9 42 7c b1 d1 33 0d ?? ?? ?? ?? 01 c8 40 ff e0 } //10
		$a_03_1 = {89 ce 21 de 01 f6 29 de 01 d6 21 ce 89 f5 81 e5 ?? ?? ?? ?? 89 f0 83 e0 02 89 f7 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}