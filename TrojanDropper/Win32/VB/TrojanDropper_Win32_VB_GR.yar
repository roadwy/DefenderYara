
rule TrojanDropper_Win32_VB_GR{
	meta:
		description = "TrojanDropper:Win32/VB.GR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 6d 00 6d 00 74 00 6d 00 70 00 2e 00 62 00 61 00 74 00 } //01 00  \mmtmp.bat
		$a_01_1 = {6e 00 65 00 74 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 51 00 6f 00 53 00 76 00 63 00 } //01 00  net start QoSvc
		$a_01_2 = {43 00 55 00 53 00 54 00 4f 00 4d 00 00 00 00 00 18 00 00 00 5c 00 43 00 6f 00 6d 00 5c 00 51 00 6f 00 73 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_00_3 = {69 6e 73 74 61 6c 6c 00 61 70 70 00 00 61 70 70 } //01 00  湩瑳污l灡p愀灰
		$a_00_4 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //00 00  MSVBVM60.DLL
	condition:
		any of ($a_*)
 
}