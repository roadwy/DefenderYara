
rule Trojan_Win32_Neoreblamy_NUW_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NUW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 09 8b 55 c8 83 c2 01 89 55 c8 83 7d c8 01 7d 10 8b 45 c8 } //1
		$a_03_1 = {6b d1 00 8b 85 ?? ?? ff ff 89 44 15 a8 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}