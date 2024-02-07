
rule Trojan_Win64_T1070_001_ClearWindowsEventLogs_A{
	meta:
		description = "Trojan:Win64/T1070_001_ClearWindowsEventLogs.A,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {65 00 76 00 65 00 6e 00 74 00 3a 00 3a 00 63 00 6c 00 65 00 61 00 72 00 } //00 00  event::clear
	condition:
		any of ($a_*)
 
}