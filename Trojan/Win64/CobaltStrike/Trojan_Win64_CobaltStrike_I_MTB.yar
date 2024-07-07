
rule Trojan_Win64_CobaltStrike_I_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 98 0f b6 94 05 90 01 01 02 00 00 8b 85 90 01 02 00 00 48 98 0f b6 84 05 b0 01 00 00 31 c2 8b 85 90 01 02 00 00 48 98 88 54 05 b0 83 85 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}