
rule Trojan_Win64_CobaltStrike_N_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c2 48 8d 4d f4 48 03 c8 ff c2 0f b6 01 41 2a c1 41 32 c0 88 01 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}