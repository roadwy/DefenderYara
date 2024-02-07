
rule Trojan_Win32_Redcap_BB_MSR{
	meta:
		description = "Trojan:Win32/Redcap.BB!MSR,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {4e 6f 61 64 66 67 69 6f 61 65 6a 66 69 67 6f 61 65 66 } //01 00  Noadfgioaejfigoaef
		$a_81_1 = {4e 6f 65 61 6a 69 6f 66 67 73 65 61 6a 69 67 66 65 73 69 66 67 } //01 00  Noeajiofgseajigfesifg
		$a_81_2 = {41 72 65 46 69 6c 65 41 70 69 73 41 4e 53 49 } //01 00  AreFileApisANSI
		$a_81_3 = {47 65 74 4e 75 6d 61 48 69 67 68 65 73 74 4e 6f 64 65 4e 75 6d 62 65 72 } //01 00  GetNumaHighestNodeNumber
		$a_81_4 = {47 65 74 53 79 73 74 65 6d 46 69 72 6d 77 61 72 65 54 61 62 6c 65 } //01 00  GetSystemFirmwareTable
		$a_81_5 = {49 6e 69 74 69 61 6c 69 7a 65 53 52 57 4c 6f 63 6b } //01 00  InitializeSRWLock
		$a_81_6 = {54 72 79 45 6e 74 65 72 43 72 69 74 69 63 61 6c 53 65 63 74 69 6f 6e } //01 00  TryEnterCriticalSection
		$a_81_7 = {47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 73 } //00 00  GetLogicalDrives
	condition:
		any of ($a_*)
 
}