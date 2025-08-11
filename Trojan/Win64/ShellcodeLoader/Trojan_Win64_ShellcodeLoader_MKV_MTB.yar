
rule Trojan_Win64_ShellcodeLoader_MKV_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeLoader.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 1e 32 18 48 8b 95 58 02 00 00 48 83 ec 20 48 89 f9 e8 12 a3 00 00 48 83 c4 20 88 18 48 8b 9d ?? ?? ?? ?? 48 83 c3 01 b8 56 e9 d3 fd 3d e3 8d 0c 15 0f 8e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}