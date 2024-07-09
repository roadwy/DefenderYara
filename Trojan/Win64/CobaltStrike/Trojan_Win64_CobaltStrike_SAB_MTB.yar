
rule Trojan_Win64_CobaltStrike_SAB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 14 03 48 ?? ?? 39 f8 89 c2 7c 90 0a 16 00 83 e2 ?? 8a 54 15 ?? 41 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}