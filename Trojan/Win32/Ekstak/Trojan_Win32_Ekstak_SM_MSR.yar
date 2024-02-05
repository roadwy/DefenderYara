
rule Trojan_Win32_Ekstak_SM_MSR{
	meta:
		description = "Trojan:Win32/Ekstak.SM!MSR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {b7 03 2a fb a1 90 01 03 00 03 f8 66 33 c0 8a 65 f8 80 c7 14 0a c3 30 27 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_SM_MSR_2{
	meta:
		description = "Trojan:Win32/Ekstak.SM!MSR,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {03 c3 03 c1 6a 00 6a 00 6a 00 8a 08 6a 00 32 ca 6a 00 88 08 } //00 00 
	condition:
		any of ($a_*)
 
}