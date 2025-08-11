
rule Trojan_Win32_Neoreblamy_NJI_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NJI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 08 8b 45 d4 40 40 89 45 d4 83 7d d4 } //1
		$a_03_1 = {6a 04 58 d1 e0 8b 84 05 ?? ?? ff ff 40 6a 04 59 d1 e1 89 84 0d ?? ?? ff ff 6a 04 58 d1 e0 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}