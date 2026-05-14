
rule Trojan_Win64_CobaltStrike_FVD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.FVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8d 44 24 ?? 0f 1f 44 00 00 80 70 ?? ?? 48 83 c0 01 48 39 c2 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}