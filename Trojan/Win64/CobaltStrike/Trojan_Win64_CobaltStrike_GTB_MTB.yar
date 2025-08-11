
rule Trojan_Win64_CobaltStrike_GTB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 da 48 89 44 24 ?? 4d 63 c8 41 83 c0 ?? 47 0f b6 0c 0a 44 30 0a 4c 8d 4a ?? 4d 39 cb ?? ?? 41 83 f8 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}