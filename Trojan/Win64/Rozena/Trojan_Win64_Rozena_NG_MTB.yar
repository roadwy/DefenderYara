
rule Trojan_Win64_Rozena_NG_MTB{
	meta:
		description = "Trojan:Win64/Rozena.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8d 14 c5 00 00 00 00 48 8b 85 ?? ?? ?? ?? 48 01 d0 48 8b 00 8b 95 ?? ?? ?? ?? 48 63 d2 48 8d 0c d5 ?? ?? ?? ?? 48 8b 95 28 08 00 00 } //3
		$a_01_1 = {48 c7 44 24 40 00 00 00 00 48 8d 85 08 08 00 00 48 89 44 24 38 48 c7 44 24 30 00 00 00 00 c7 44 24 28 1f 00 02 00 c7 44 24 20 00 00 00 00 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*3) >=6
 
}