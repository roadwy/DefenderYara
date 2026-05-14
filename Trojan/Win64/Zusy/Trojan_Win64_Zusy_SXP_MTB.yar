
rule Trojan_Win64_Zusy_SXP_MTB{
	meta:
		description = "Trojan:Win64/Zusy.SXP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 02 00 00 "
		
	strings :
		$a_03_0 = {35 ef 38 87 03 89 01 8b 42 ?? 35 bf 1e 66 b4 89 41 ?? 8b 42 ?? 35 78 0b ba 19 89 41 ?? 8b 42 ?? 35 bf a5 3c d7 } //30
		$a_03_1 = {21 48 ff c0 41 03 ?? 44 0f be 10 45 85 d2 75 ee } //10
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*10) >=40
 
}