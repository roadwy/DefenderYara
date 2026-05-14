
rule Trojan_Win32_Neoreblamy_NRH_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NRH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {7d 69 83 65 bc 00 eb 07 8b 45 bc 40 89 45 bc } //1
		$a_01_1 = {7d 51 8b 45 b4 8b 4d dc d3 e0 8b 4d bc d3 e0 23 45 d4 99 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}