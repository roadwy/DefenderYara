
rule Trojan_Win64_Rozena_NER_MTB{
	meta:
		description = "Trojan:Win64/Rozena.NER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 8d 04 02 48 63 c1 48 69 c0 ?? ?? ?? ?? 48 c1 e8 20 89 c2 } //3
		$a_03_1 = {01 d0 8d 14 85 ?? ?? ?? ?? 01 d0 29 c1 89 ca 41 89 10 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}