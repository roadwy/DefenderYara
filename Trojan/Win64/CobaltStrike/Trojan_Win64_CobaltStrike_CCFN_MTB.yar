
rule Trojan_Win64_CobaltStrike_CCFN_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 83 f1 01 49 ff c0 42 03 44 8c ?? 3d ?? ?? ?? ?? 7d ?? 41 0f b6 0c 38 48 63 d0 42 88 0c 1a eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}