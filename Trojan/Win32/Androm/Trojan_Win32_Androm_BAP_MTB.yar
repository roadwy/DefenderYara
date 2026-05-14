
rule Trojan_Win32_Androm_BAP_MTB{
	meta:
		description = "Trojan:Win32/Androm.BAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 ef 66 18 00 00 2b f8 6a 00 e8 ?? ?? ?? ?? 2b f8 6a 00 e8 ?? ?? ?? ?? 2b f8 31 3e 83 c3 04 83 c6 04 3b 5d ?? 0f 82 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Androm_BAP_MTB_2{
	meta:
		description = "Trojan:Win32/Androm.BAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c2 8b f8 6a 00 e8 ?? ?? ?? ?? 03 7d a4 81 ef 84 66 00 00 2b f8 6a 00 e8 ?? ?? ?? ?? 03 f8 6a 00 e8 ?? ?? ?? ?? 2b f8 6a 00 e8 ?? ?? ?? ?? 2b f8 6a 00 e8 ?? ?? ?? ?? 2b f8 31 3e 6a 00 e8 ?? ?? ?? ?? bf 04 00 00 00 2b f8 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Androm_BAP_MTB_3{
	meta:
		description = "Trojan:Win32/Androm.BAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ba 00 10 00 00 b8 80 ?? ?? 00 03 45 ?? 2b c2 83 c0 04 89 45 ?? ff 75 ?? b9 } //2
		$a_03_1 = {ba 00 10 00 00 b8 80 ?? ?? 00 03 45 ?? 2b c2 83 c0 04 89 45 ?? ff 75 [0-05] ba } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=2
 
}