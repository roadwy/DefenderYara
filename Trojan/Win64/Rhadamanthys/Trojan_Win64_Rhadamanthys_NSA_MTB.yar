
rule Trojan_Win64_Rhadamanthys_NSA_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 d9 4c 8b 44 24 30 48 89 c2 48 8d 05 ?? ?? ?? ?? 31 c1 89 c8 31 d0 eb 85 } //3
		$a_03_1 = {48 69 c9 1f 85 eb 51 48 c1 e9 ?? 6b c9 ?? 29 c8 8d 4c 07 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}