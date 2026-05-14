
rule Trojan_Win32_Neoreblamy_NUZ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NUZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 09 8b 4d c8 83 c1 01 89 4d c8 83 7d c8 01 7d 0d 8b 55 c8 } //1
		$a_03_1 = {6b c8 00 8b 94 0d ?? ?? ff ff 83 c2 01 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}