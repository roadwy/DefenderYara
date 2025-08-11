
rule Trojan_Win64_CobaltStrike_GZQ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 88 3c 30 48 ff c6 48 89 b5 ?? ?? ?? ?? 48 81 fe ?? ?? ?? ?? ?? ?? 89 f0 83 e0 0f 46 0f b6 3c 36 44 32 bc 05 ?? ?? ?? ?? 48 3b b5 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}