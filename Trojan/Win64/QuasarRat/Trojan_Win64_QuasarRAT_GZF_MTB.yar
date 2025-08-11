
rule Trojan_Win64_QuasarRAT_GZF_MTB{
	meta:
		description = "Trojan:Win64/QuasarRAT.GZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 03 f5 45 8b 66 ?? 45 8b 6e ?? 4c 03 e5 41 8b 46 ?? 4c 03 ed 48 03 c5 48 89 44 24 ?? 41 39 7e ?? ?? ?? 66 66 0f 1f 84 00 00 00 00 00 41 8b 0c bc 48 8d 15 ?? ?? ?? ?? 48 03 cd 41 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? ff c7 41 3b 7e 18 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}