
rule Trojan_Win32_Neoreblamy_RA_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 4c 24 10 57 8b c2 99 6a 18 5b f7 fb 89 5c 24 24 8b f0 8b 45 08 2b c1 89 74 24 20 99 8b fe f7 fb 89 44 24 1c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}