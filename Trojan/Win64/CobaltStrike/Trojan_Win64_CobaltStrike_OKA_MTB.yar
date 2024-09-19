
rule Trojan_Win64_CobaltStrike_OKA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.OKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 31 aa 48 ff c1 48 8b c1 48 2b c7 48 3b c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}