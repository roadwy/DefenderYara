
rule Trojan_Win64_ZetaNile_A{
	meta:
		description = "Trojan:Win64/ZetaNile.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_43_0 = {ff 41 b9 14 00 00 00 c7 44 24 30 14 00 00 00 90 0a 20 00 49 8b cc e8 90 01 02 00 00 48 8b f8 e8 90 00 01 } //1
		$a_38_2 = {37 34 2e 38 34 01 00 1a 00 53 6f 66 74 77 61 72 65 5c 53 69 6d 6f 6e 54 61 74 68 61 6d 5c 50 75 54 54 59 00 00 02 00 5d 04 00 00 23 4e 05 80 5c 22 00 00 } //12846
	condition:
		((#a_43_0  & 1)*1+(#a_38_2  & 1)*12846) >=3
 
}