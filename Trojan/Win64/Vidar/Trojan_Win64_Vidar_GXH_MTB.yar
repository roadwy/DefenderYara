
rule Trojan_Win64_Vidar_GXH_MTB{
	meta:
		description = "Trojan:Win64/Vidar.GXH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 72 0f b6 44 24 20 48 83 c4 48 c3 } //5
		$a_03_1 = {32 00 00 00 f2 d1 eb 01 b2 ?? ?? ?? ?? ea cd 74 03 ba ?? ?? ?? ?? 44 24 00 09 eb 01 9a ?? ?? ?? ?? fc } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}