
rule Trojan_Win64_CobaltStrike_MG_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 c1 48 31 d2 49 89 d8 4d 31 c9 52 68 00 02 40 84 52 52 41 ba eb 55 2e 3b ff d5 48 89 c6 48 83 c3 50 6a 0a 5f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}