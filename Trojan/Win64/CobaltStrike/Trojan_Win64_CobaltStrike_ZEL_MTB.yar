
rule Trojan_Win64_CobaltStrike_ZEL_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 33 c4 48 89 85 80 00 00 00 48 8b f2 48 8b f9 45 33 ed 44 89 6c 24 20 48 8b 49 28 4c 8b 77 38 49 c1 e6 06 4c 03 f1 49 c1 e6 03 48 8b 57 30 48 3b ca } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}