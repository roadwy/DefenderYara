
rule Trojan_Win64_Rozena_NK_MTB{
	meta:
		description = "Trojan:Win64/Rozena.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 2d da 17 98 00 48 8b 35 7b 60 98 00 65 48 8b 04 25 ?? ?? ?? ?? 48 8b 58 08 31 c0 f0 48 0f b1 5d 00 74 0e } //3
		$a_03_1 = {74 0d b9 e8 03 00 00 ff d6 eb e8 31 f6 eb 05 be ?? ?? ?? ?? 48 8b 1d ae 17 98 00 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}