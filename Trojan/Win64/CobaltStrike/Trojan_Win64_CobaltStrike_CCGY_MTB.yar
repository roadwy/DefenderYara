
rule Trojan_Win64_CobaltStrike_CCGY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCGY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 54 81 ?? 81 74 95 ?? ?? ?? ?? ?? 48 63 14 81 81 74 95 ?? ?? ?? ?? ?? 48 83 c0 ?? 48 83 f8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}