
rule Trojan_Win32_GreenMach_gen_dha{
	meta:
		description = "Trojan:Win32/GreenMach.gen!dha,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_43_0 = {7d 08 00 00 10 00 7c 07 b8 08 00 00 00 eb 90 01 01 8b 45 fc 83 38 00 74 90 01 01 8b 4d fc 8b 11 89 55 f8 8b 45 f8 90 00 05 } //5
		$a_b9_1 = {00 00 00 66 89 8d 90 01 04 33 d2 66 89 95 90 01 04 6a 08 8d 8d 90 01 04 e8 90 01 04 8d 8d 90 01 04 e8 90 00 00 00 5d 04 00 00 84 01 05 80 5c 2c 00 00 85 01 05 80 00 00 01 00 08 00 16 00 ac 21 47 72 65 } //9728
	condition:
		((#a_43_0  & 1)*5+(#a_b9_1  & 1)*9728) >=10
 
}