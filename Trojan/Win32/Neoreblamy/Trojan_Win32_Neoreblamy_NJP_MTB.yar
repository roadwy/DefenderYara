
rule Trojan_Win32_Neoreblamy_NJP_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NJP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 a8 40 89 45 a8 83 7d a8 01 7d 0d 8b 45 a8 } //1
		$a_03_1 = {6a 04 58 6b c0 00 8b 8d ?? ?? ff ff 89 4c 05 dc } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}