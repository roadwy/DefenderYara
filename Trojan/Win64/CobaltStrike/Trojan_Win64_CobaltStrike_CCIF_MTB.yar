
rule Trojan_Win64_CobaltStrike_CCIF_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCIF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8a 44 35 90 01 01 41 32 84 1f 90 01 04 48 ff c3 83 e3 0f 88 44 37 90 01 01 48 ff c6 e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}