
rule Trojan_Win32_Neoreblamy_NUI_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NUI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {7d 4c 83 65 a4 00 eb 07 8b 45 a4 40 89 45 a4 81 7d a4 } //1
		$a_03_1 = {8b 4d 9c d3 e0 8b 8d ?? ?? ff ff d3 f8 99 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}