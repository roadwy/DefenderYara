
rule Trojan_Win32_Neoreblamy_NJZ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NJZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 fc 40 89 45 fc 83 7d fc 03 7d 10 8b 45 fc } //2
		$a_03_1 = {6a 04 58 d1 e0 8b 84 05 ?? ff ff ff 40 6a 04 59 d1 e1 89 84 0d ?? ff ff ff 6a 04 58 d1 e0 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}