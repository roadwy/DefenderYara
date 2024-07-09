
rule Trojan_Win64_Lazy_GZY_MTB{
	meta:
		description = "Trojan:Win64/Lazy.GZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 03 c6 4c 89 64 24 ?? 48 89 45 ?? ff 15 ?? ?? ?? ?? 48 8b 4c 24 ?? 48 8d 54 24 ?? ff 15 ?? ?? ?? ?? 48 8b 4c 24 ?? ff 15 ?? ?? ?? ?? 49 8b cd e8 } //5
		$a_03_1 = {44 8b 03 8b 53 f8 4d 03 c5 44 8b ?? fc 49 03 d6 48 8b 4c 24 ?? 4c 89 64 24 ?? ff 15 ?? ?? ?? ?? 0f b7 46 ?? 48 8d 5b ?? ff c7 3b f8 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}