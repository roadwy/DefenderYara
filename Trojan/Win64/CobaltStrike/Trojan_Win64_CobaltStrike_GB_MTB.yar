
rule Trojan_Win64_CobaltStrike_GB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 8a 14 10 } //1
		$a_02_1 = {44 30 14 0f 48 ff c1 48 89 c8 48 81 f9 [0-04] 0f 86 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}