
rule Trojan_Win64_ClearFake_YAA_MTB{
	meta:
		description = "Trojan:Win64/ClearFake.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {29 45 e3 48 31 45 92 89 55 84 28 75 f1 b9 } //1
		$a_03_1 = {44 30 27 48 8d 05 ?? ?? ?? ?? 50 53 57 56 41 55 41 54 55 48 89 e5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}