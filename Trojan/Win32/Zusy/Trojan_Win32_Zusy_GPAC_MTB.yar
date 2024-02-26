
rule Trojan_Win32_Zusy_GPAC_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GPAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {8a 84 1c 30 01 00 00 30 86 90 01 04 46 8b 5c 24 1c 8b 54 24 10 81 fe 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zusy_GPAC_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.GPAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 41 74 74 65 6e 64 61 6e 63 65 52 53 } //01 00  CAttendanceRS
		$a_01_1 = {4f 44 42 43 3b 44 53 4e 3d 4d 49 53 44 42 } //01 00  ODBC;DSN=MISDB
		$a_01_2 = {5b 50 45 52 53 4f 4e 5d 00 00 00 00 5b 49 44 5d } //01 00 
		$a_81_3 = {43 45 72 72 61 6e 64 52 53 } //01 00  CErrandRS
		$a_81_4 = {43 4c 65 61 76 65 52 53 } //00 00  CLeaveRS
	condition:
		any of ($a_*)
 
}