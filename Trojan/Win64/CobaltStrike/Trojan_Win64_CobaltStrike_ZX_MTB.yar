
rule Trojan_Win64_CobaltStrike_ZX_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f af c1 89 42 70 48 8b 15 d4 f2 02 00 8b 05 ea f3 02 00 05 3f 25 ee ff 8b 8a 2c 01 00 00 33 0d 05 f3 02 00 03 c8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}