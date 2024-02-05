
rule Trojan_Win32_Emotet_OS_MSR{
	meta:
		description = "Trojan:Win32/Emotet.OS!MSR,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 00 6a 00 6a 00 ff d6 6a 00 6a 00 6a 00 ff d6 6a 00 6a 00 6a 00 ff d6 6a 00 6a 00 6a 00 ff d6 55 e8 6a } //00 00 
	condition:
		any of ($a_*)
 
}