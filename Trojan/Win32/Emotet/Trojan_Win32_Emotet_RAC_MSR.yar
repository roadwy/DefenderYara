
rule Trojan_Win32_Emotet_RAC_MSR{
	meta:
		description = "Trojan:Win32/Emotet.RAC!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {03 c2 99 bb 90 01 04 f7 fb 45 0f b6 c2 8a 0c 08 8b 44 24 90 01 01 30 4c 28 90 01 01 3b 6c 24 90 01 01 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}