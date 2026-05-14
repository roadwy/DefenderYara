
rule Trojan_Win32_Copak_BAJ_MTB{
	meta:
		description = "Trojan:Win32/Copak.BAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 1a 21 f6 88 1f 29 f1 81 c7 01 00 00 00 01 f1 81 c2 02 00 00 00 81 c1 84 ca 43 d3 21 f6 89 f1 39 c2 7e } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Copak_BAJ_MTB_2{
	meta:
		description = "Trojan:Win32/Copak.BAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 11 21 f3 88 17 4e 47 89 de 89 f3 4b 81 c1 02 00 00 00 81 ee 01 00 00 00 21 de 01 f6 39 c1 7e } //2
		$a_01_1 = {01 d3 88 06 42 46 09 d3 81 c1 02 00 00 00 21 db 4a 39 f9 7e } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}