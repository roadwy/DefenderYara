
rule Trojan_Win32_Ekstak_RM_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 10 53 56 57 e8 a2 07 f6 ff e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_RM_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {56 68 01 ef 64 00 e8 05 72 fb ff 8b f0 e9 } //1
		$a_01_1 = {56 68 31 ef 64 00 e8 85 71 fb ff 8b f0 e9 } //1
		$a_01_2 = {56 68 21 ef 64 00 e8 85 71 fb ff 8b f0 e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}