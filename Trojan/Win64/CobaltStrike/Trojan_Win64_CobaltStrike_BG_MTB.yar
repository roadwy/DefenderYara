
rule Trojan_Win64_CobaltStrike_BG_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 8b e8 00 00 00 8b 83 80 00 00 00 42 31 04 09 49 83 c1 04 8b 8b f4 00 00 00 01 8b 80 00 00 00 8b 4b 10 29 8b 88 00 00 00 8b 8b 88 00 00 00 81 c1 ba c5 1a 00 31 8b b4 00 00 00 49 81 f9 20 df 01 00 7c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}