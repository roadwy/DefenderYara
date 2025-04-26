
rule Trojan_Win32_Skraer_A{
	meta:
		description = "Trojan:Win32/Skraer.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 07 89 55 ?? 84 c0 74 ?? 3c 66 75 ?? 8b c7 33 c9 8a 14 02 8a 18 3a da 75 01 } //1
		$a_03_1 = {8b 75 08 57 8d 86 ?? ?? 00 00 50 8b 46 04 c7 45 ?? 00 00 00 00 ff d0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}