
rule Trojan_Win32_Neoreblamy_NLF_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NLF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {eb 08 8b 45 e0 40 40 89 45 e0 83 7d e0 1e } //2
		$a_01_1 = {eb 07 8b 45 80 40 89 45 80 83 7d 80 03 7d 10 8b 45 80 } //1
		$a_03_2 = {eb d7 6a 04 58 6b c0 03 8b 84 05 ?? ?? ff ff 40 6a 04 59 6b c9 03 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=4
 
}