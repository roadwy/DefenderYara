
rule Trojan_Win32_RedLine_MQ_MTB{
	meta:
		description = "Trojan:Win32/RedLine.MQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {47 6f 6f 64 20 68 41 4b 4a 62 31 37 20 78 68 56 67 73 32 37 } //05 00  Good hAKJb17 xhVgs27
		$a_03_1 = {83 c4 04 89 45 ec c7 45 fc 00 00 00 00 8d 4d c0 6a 14 c7 45 c0 00 00 00 00 68 90 01 04 c7 45 d0 00 00 00 00 c7 45 d4 0f 00 00 00 c6 45 c0 00 e8 90 00 } //05 00 
		$a_01_2 = {e0 00 02 01 0b 01 0e 20 00 56 07 00 00 06 04 00 00 00 00 00 ba 4a 02 } //02 00 
		$a_01_3 = {49 6e 69 74 4f 6e 63 65 45 78 65 63 75 74 65 4f 6e 63 65 } //02 00  InitOnceExecuteOnce
		$a_01_4 = {47 65 74 54 69 6d 65 5a 6f 6e 65 49 6e 66 6f 72 6d 61 74 69 6f 6e } //00 00  GetTimeZoneInformation
	condition:
		any of ($a_*)
 
}