
rule Trojan_Win32_Neoreblamy_NMI_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 e8 40 89 45 e8 83 7d e8 03 } //1
		$a_03_1 = {6a 04 58 6b c0 03 8b 84 05 ?? ?? ff ff 6a 04 59 6b c9 03 } //2
		$a_03_2 = {eb 1b 6a 04 58 6b c0 03 8b 84 05 ?? ?? ff ff 48 6a 04 59 6b c9 03 89 84 0d ?? ?? ff ff 6a 04 58 6b c0 03 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1) >=4
 
}