
rule Trojan_Win32_Neoreblamy_NTL_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NTL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 04 58 d1 e0 8d 84 05 ?? ?? ff ff 6a 04 59 } //1
		$a_01_1 = {eb 07 8b 45 e4 40 89 45 e4 83 7d e4 05 7d 10 8b 45 e4 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}