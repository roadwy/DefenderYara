
rule Trojan_Win32_Neoreblamy_NRP_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NRP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {7d 46 83 65 c4 00 eb 07 8b 45 c4 40 89 45 c4 } //1
		$a_01_1 = {eb 07 8b 45 e0 40 89 45 e0 81 7d e0 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}