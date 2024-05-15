
rule Trojan_Win32_Ekstak_RK_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 08 56 57 e8 e3 6d fb ff 8b f8 e9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RK_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 08 56 57 68 3e e1 64 00 e8 1e 6e fb ff 8b f8 e9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RK_MTB_3{
	meta:
		description = "Trojan:Win32/Ekstak.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 08 56 57 e8 23 6e fb ff 8b f8 e9 } //01 00 
		$a_01_1 = {40 00 00 40 2e 47 49 46 } //00 00  @䀀䜮䙉
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RK_MTB_4{
	meta:
		description = "Trojan:Win32/Ekstak.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 05 7c 4b 08 01 68 90 01 04 e8 90 01 01 00 00 00 59 a3 90 01 01 4b 08 01 e8 90 01 01 00 00 00 8b c8 b8 90 01 04 33 d2 f7 f1 31 05 90 01 01 4b 08 01 e8 90 01 02 00 00 33 c0 50 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}