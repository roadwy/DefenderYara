
rule Trojan_Win32_Neoreblamy_NIE_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NIE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 dc 40 89 45 dc 83 7d dc 02 7d 10 8b 45 dc } //1
		$a_03_1 = {6a 04 59 6b c9 00 3b 84 0d ?? ?? ff ff 7f 0c } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}
rule Trojan_Win32_Neoreblamy_NIE_MTB_2{
	meta:
		description = "Trojan:Win32/Neoreblamy.NIE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 c4 40 89 45 c4 83 7d c4 ?? 7d 10 8b 45 c4 } //1
		$a_03_1 = {eb 07 83 a5 ?? ff ff ff 00 6a 04 58 6b c0 03 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}