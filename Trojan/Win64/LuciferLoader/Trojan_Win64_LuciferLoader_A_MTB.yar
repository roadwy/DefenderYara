
rule Trojan_Win64_LuciferLoader_A_MTB{
	meta:
		description = "Trojan:Win64/LuciferLoader.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 9c 24 ?? ?? ?? ?? 41 0f b7 5e ?? 48 89 bc 24 ?? ?? ?? ?? 48 83 c3 ?? 41 8b fd 66 41 39 7e } //2
		$a_01_1 = {30 14 08 48 ff c0 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}