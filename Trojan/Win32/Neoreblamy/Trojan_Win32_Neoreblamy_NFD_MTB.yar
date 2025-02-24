
rule Trojan_Win32_Neoreblamy_NFD_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NFD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {7d 64 83 65 e0 00 eb 07 8b 45 e0 40 89 45 e0 } //2
		$a_01_1 = {eb 07 8b 45 c0 40 89 45 c0 83 7d c0 01 7d 10 8b 45 c0 } //1
		$a_01_2 = {7d 45 83 65 e8 00 eb 07 8b 45 e8 40 89 45 e8 81 7d e8 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}