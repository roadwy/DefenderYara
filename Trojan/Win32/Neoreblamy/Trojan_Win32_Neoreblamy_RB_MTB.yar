
rule Trojan_Win32_Neoreblamy_RB_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 4d f8 57 8b c2 99 6a 18 5b f7 fb 89 5d e8 8b f0 8b 45 08 2b c1 89 75 ec 99 8b fe f7 fb 89 45 f0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Neoreblamy_RB_MTB_2{
	meta:
		description = "Trojan:Win32/Neoreblamy.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 7d 08 01 75 1c e8 ?? ?? ?? ?? 99 6a 03 59 f7 f9 42 42 69 c2 e8 03 00 00 50 ff 15 ?? ?? ?? ?? eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}