
rule Trojan_Win32_Convagent_AMMI_MTB{
	meta:
		description = "Trojan:Win32/Convagent.AMMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c6 30 08 83 fb 0f 75 ?? 6a 2e 8d 45 cc } //1
		$a_03_1 = {30 04 37 83 7d 08 0f 75 ?? 6a 2e 8d 45 cc } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Convagent_AMMI_MTB_2{
	meta:
		description = "Trojan:Win32/Convagent.AMMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 [0-05] 33 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}