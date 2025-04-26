
rule Trojan_Win32_Neoreblamy_NFM_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 a0 40 89 45 a0 83 7d a0 00 7f 11 8b 45 a0 } //2
		$a_03_1 = {eb 1b 6a 04 58 6b c0 00 8b 84 05 ?? ?? ff ff 40 6a 04 59 6b c9 00 89 84 0d ?? ?? ff ff 6a 04 58 6b c0 00 } //1
		$a_01_2 = {eb 07 8b 45 cc 40 89 45 cc 83 7d cc 01 7d 10 8b 45 cc } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}