
rule Trojan_Win32_Neoreblamy_NUX_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NUX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 e8 40 89 45 e8 83 7d e8 01 7d 0d 8b 45 e8 } //1
		$a_03_1 = {6b c0 00 8b 8d ?? ?? ff ff 89 4c 05 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}