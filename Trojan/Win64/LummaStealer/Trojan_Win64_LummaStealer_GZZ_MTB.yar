
rule Trojan_Win64_LummaStealer_GZZ_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 de 81 fb ?? ?? ?? ?? 0f 85 ?? ?? ?? ?? 0f b6 19 30 d3 88 5c 24 27 44 89 d6 } //10
		$a_03_1 = {44 89 d5 81 ff ?? ?? ?? ?? ?? ?? 89 fd 81 ff ?? ?? ?? ?? ?? ?? 0f b6 19 30 d3 88 5c 24 27 44 89 f5 eb } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}