
rule Trojan_Win32_Remcos_ACS_MTB{
	meta:
		description = "Trojan:Win32/Remcos.ACS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 7b 0c 8b cd e8 76 ?? ?? ?? 8b cb 8b f0 e8 6d ?? ?? ?? 33 f0 23 74 24 10 31 34 97 42 8b 33 3b d6 7c dd } //3
		$a_03_1 = {c1 ee 03 6a 13 5a 8b cb 33 fe e8 d6 ?? ?? ?? 6a 11 5a 8b cb 8b f0 e8 ca ?? ?? ?? 33 f0 c1 eb 0a 33 f3 8d 6d 04 03 fe 03 7d c4 03 7d e8 83 6c 24 28 01 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}