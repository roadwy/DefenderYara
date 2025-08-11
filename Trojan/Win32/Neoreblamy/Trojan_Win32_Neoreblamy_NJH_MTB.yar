
rule Trojan_Win32_Neoreblamy_NJH_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NJH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 80 40 89 45 80 83 7d 80 04 7d 10 8b 45 80 } //1
		$a_03_1 = {6a 04 58 6b c0 00 8b 44 05 b0 89 85 ?? ?? ff ff 6a 04 58 c1 e0 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}