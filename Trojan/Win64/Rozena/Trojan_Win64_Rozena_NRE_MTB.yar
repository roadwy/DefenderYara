
rule Trojan_Win64_Rozena_NRE_MTB{
	meta:
		description = "Trojan:Win64/Rozena.NRE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 8b 0f 45 85 c9 0f 85 9c 02 00 00 65 48 8b 04 25 ?? ?? ?? ?? 48 8b 1d 0c 92 05 00 48 8b 70 ?? 31 ed 4c 8b 25 0b e0 05 00 eb 16 } //3
		$a_03_1 = {48 85 c0 75 e2 48 8b 35 e3 91 05 00 31 ed 8b 06 83 f8 ?? 0f 84 05 02 00 00 8b 06 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}