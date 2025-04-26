
rule Trojan_Win32_Neoreblamy_NMB_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 13 6a 04 58 d1 e0 8b 44 05 84 40 6a 04 59 d1 e1 89 44 0d 84 6a 04 58 d1 e0 } //2
		$a_01_1 = {eb 07 8b 45 f4 40 89 45 f4 83 7d f4 01 7d 0d 8b 45 f4 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}