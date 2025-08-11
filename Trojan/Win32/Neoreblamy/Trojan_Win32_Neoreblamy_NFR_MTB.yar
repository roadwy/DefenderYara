
rule Trojan_Win32_Neoreblamy_NFR_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 04 58 d1 e0 8b 84 05 ?? ff ff ff 6a 04 59 6b c9 00 } //1
		$a_03_1 = {eb 07 8b 45 c0 40 89 45 c0 83 7d c0 ?? 7d 10 8b 45 c0 } //2
		$a_03_2 = {6a 04 58 6b c0 00 8b 84 05 ?? ?? ff ff 48 89 85 ?? ?? ff ff 6a 04 58 6b c0 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1) >=4
 
}