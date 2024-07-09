
rule Trojan_Win32_Neoreblamy_E_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 40 89 45 fc 83 7d fc 02 7d ?? 8b 45 fc c7 84 85 88 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}