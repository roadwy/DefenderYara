
rule Trojan_Win32_Neoreblamy_NMY_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NMY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 f0 40 89 45 f0 83 7d f0 03 7f 11 8b 45 f0 } //1
		$a_03_1 = {eb 1b 6a 04 58 6b c0 00 8b 84 05 ?? ?? ff ff 40 6a 04 59 6b c9 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}