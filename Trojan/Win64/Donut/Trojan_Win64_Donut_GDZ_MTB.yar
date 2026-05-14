
rule Trojan_Win64_Donut_GDZ_MTB{
	meta:
		description = "Trojan:Win64/Donut.GDZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {bb 03 00 00 00 48 8b 35 ?? ?? ?? ?? b9 00 00 00 00 ff d6 4d 89 e4 4d 89 ed 83 eb } //5
		$a_03_1 = {41 b9 40 00 00 00 41 b8 00 30 00 00 ba 00 02 00 00 b9 00 00 00 00 ff 15 ?? ?? ?? ?? 48 89 c6 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}