
rule Trojan_Win64_CobaltStrike_UTI_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.UTI!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 8b 87 08 01 00 00 33 c9 44 2b 47 18 8b 57 10 41 81 e8 ff 55 00 00 44 8d 49 40 ff 15 39 49 00 00 } //1
		$a_01_1 = {0f af c2 41 8b d0 89 43 64 2b 83 e8 00 00 00 89 43 64 48 8b 83 90 00 00 00 c1 ea 08 88 14 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}