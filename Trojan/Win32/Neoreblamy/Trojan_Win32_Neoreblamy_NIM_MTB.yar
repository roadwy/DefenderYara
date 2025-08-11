
rule Trojan_Win32_Neoreblamy_NIM_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NIM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 02 58 d1 e0 33 c9 66 89 8c 05 } //1
		$a_01_1 = {eb 08 8b 45 f8 40 40 89 45 f8 83 7d f8 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}