
rule Trojan_Win64_CobaltStrike_QI_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.QI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8a 04 36 32 84 1f 90 01 04 48 ff c3 41 88 44 35 90 01 01 83 e3 90 01 01 48 ff c6 e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}