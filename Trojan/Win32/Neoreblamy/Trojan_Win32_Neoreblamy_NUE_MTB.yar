
rule Trojan_Win32_Neoreblamy_NUE_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NUE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 e4 48 89 45 e4 83 7d e4 e9 } //2
		$a_01_1 = {eb 07 8b 45 dc 40 89 45 dc 83 7d dc 01 7d 10 8b 45 dc } //2
		$a_03_2 = {6a 04 58 6b c0 00 83 bc 05 ?? ?? ff ff 00 74 22 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*1) >=5
 
}