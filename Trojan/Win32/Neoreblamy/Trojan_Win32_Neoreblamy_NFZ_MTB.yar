
rule Trojan_Win32_Neoreblamy_NFZ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NFZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {eb 1b 6a 04 58 6b c0 00 8b 84 05 0c ff ff ff 40 6a 04 59 6b c9 00 } //1
		$a_01_1 = {eb 07 8b 45 c0 40 89 45 c0 83 7d c0 01 7d 10 } //1
		$a_03_2 = {6a 04 5a 6b d2 00 8b 94 15 ?? ?? ff ff 4a 6a 04 5e 6b f6 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=4
 
}