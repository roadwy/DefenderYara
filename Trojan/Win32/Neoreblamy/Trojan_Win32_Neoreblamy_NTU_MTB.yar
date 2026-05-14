
rule Trojan_Win32_Neoreblamy_NTU_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NTU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 dc 40 89 45 dc 83 7d dc 03 7d 10 8b 45 dc } //2
		$a_03_1 = {c1 e1 00 8d 8c 0d ?? ?? ff ff 8b 04 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}