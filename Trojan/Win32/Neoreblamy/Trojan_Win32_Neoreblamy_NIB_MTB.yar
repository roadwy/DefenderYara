
rule Trojan_Win32_Neoreblamy_NIB_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 c4 48 89 45 c4 83 7d c4 00 } //1
		$a_03_1 = {6a 04 58 c1 e0 00 8b 84 05 ?? ?? ff ff 48 6a 04 59 c1 e1 00 89 84 0d ?? ?? ff ff 6a 04 58 c1 e0 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}