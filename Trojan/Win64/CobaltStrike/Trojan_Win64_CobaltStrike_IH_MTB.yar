
rule Trojan_Win64_CobaltStrike_IH_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.IH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 0f b6 c0 ff c2 2a 01 48 8d 49 ?? 41 32 c1 88 41 ?? 81 fa ?? ?? ?? ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}