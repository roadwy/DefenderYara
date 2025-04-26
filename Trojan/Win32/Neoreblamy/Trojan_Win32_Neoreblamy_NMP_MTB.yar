
rule Trojan_Win32_Neoreblamy_NMP_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 dc 40 89 45 dc 83 7d dc 03 7d 0d 8b 45 dc } //1
		$a_03_1 = {6a 04 58 d1 e0 8b 44 05 80 89 85 ?? ?? ff ff 6a 04 58 d1 e0 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}