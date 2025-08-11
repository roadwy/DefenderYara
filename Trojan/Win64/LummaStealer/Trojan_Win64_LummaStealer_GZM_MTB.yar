
rule Trojan_Win64_LummaStealer_GZM_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.GZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 19 30 d3 88 5c 24 ?? 44 89 ce e9 ?? ?? ?? ?? 8a 5c 24 ?? 48 8b 4c 24 28 48 31 e1 e8 ?? ?? ?? ?? 89 d8 48 83 c4 } //10
		$a_03_1 = {89 f3 81 fe 2e 9b 32 57 0f 85 ?? ?? ?? ?? 0f b6 01 30 d0 88 44 24 ?? 44 89 fb e9 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}