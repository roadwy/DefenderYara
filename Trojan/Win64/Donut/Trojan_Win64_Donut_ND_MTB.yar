
rule Trojan_Win64_Donut_ND_MTB{
	meta:
		description = "Trojan:Win64/Donut.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 8b 06 48 85 c0 74 ?? 48 89 f9 ff d0 49 8b 56 08 48 85 d2 74 ?? 4d 8b 46 10 48 89 f9 e8 3b 0c 00 00 ba 18 00 00 00 } //3
		$a_03_1 = {e9 1f 0c 00 00 48 89 c3 49 8b 56 08 48 85 d2 74 ?? 4d 8b 46 10 48 89 f9 e8 07 0c 00 00 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*1) >=4
 
}