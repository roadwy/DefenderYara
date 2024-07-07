
rule Trojan_Win64_CobaltStrike_CCAX_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 c8 41 ff c0 42 0f b6 04 09 30 02 48 ff c2 48 83 ee 01 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}