
rule Trojan_Win32_Neoreblamy_NJX_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NJX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 dc 40 89 45 dc 83 7d dc 01 7d 0d 8b 45 dc } //2
		$a_03_1 = {6a 04 58 c1 e0 00 83 bc 05 ?? ff ff ff 00 75 16 6a 04 58 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}