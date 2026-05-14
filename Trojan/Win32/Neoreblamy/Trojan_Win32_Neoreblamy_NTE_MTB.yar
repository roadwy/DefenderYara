
rule Trojan_Win32_Neoreblamy_NTE_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NTE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 9c 48 89 45 9c 83 7d 9c 00 } //1
		$a_01_1 = {7d 29 83 65 bc 00 eb 07 8b 45 bc 40 89 45 bc 81 7d bc } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}