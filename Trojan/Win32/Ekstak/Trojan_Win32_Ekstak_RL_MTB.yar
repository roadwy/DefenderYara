
rule Trojan_Win32_Ekstak_RL_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 08 56 57 68 9e cf 64 00 e8 ee 6e fb ff 8b f8 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RL_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {64 00 8b c8 33 d2 81 e1 ff 00 00 00 8a d4 83 f9 05 8b c2 75 10 83 f8 01 73 18 c7 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RL_MTB_3{
	meta:
		description = "Trojan:Win32/Ekstak.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 08 56 57 68 0e df 64 00 e8 be 6f fb ff 8b f8 e9 } //1
		$a_01_1 = {55 8b ec 83 ec 08 56 57 68 ee de 64 00 e8 ee 6f fb ff 8b f8 e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RL_MTB_4{
	meta:
		description = "Trojan:Win32/Ekstak.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 08 56 57 68 ce c0 64 00 e8 8e 6e fb ff 8b f8 e9 } //1
		$a_01_1 = {55 8b ec 83 ec 08 56 57 68 3e c1 64 00 e8 1e 6e fb ff 8b f8 e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}