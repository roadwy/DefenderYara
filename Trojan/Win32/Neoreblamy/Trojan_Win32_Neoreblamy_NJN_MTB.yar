
rule Trojan_Win32_Neoreblamy_NJN_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 90 40 89 45 90 83 7d 90 01 7d 10 8b 45 90 } //1
		$a_03_1 = {eb 1b 6a 04 58 6b c0 03 8b 84 05 ?? ?? ff ff 48 6a 04 59 6b c9 03 89 84 0d ?? ?? ff ff 6a 04 58 6b c0 03 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}