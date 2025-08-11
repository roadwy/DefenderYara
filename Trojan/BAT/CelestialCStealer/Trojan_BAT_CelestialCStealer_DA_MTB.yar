
rule Trojan_BAT_CelestialCStealer_DA_MTB{
	meta:
		description = "Trojan:BAT/CelestialCStealer.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,6a 00 6a 00 07 00 00 "
		
	strings :
		$a_01_0 = {63 65 6c 65 73 74 69 61 6c 43 2e 50 72 6f 70 65 72 74 69 65 73 } //100 celestialC.Properties
		$a_81_1 = {47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 73 } //1 GetLogicalDrives
		$a_81_2 = {67 65 74 5f 41 6c 6c 53 63 72 65 65 6e 73 } //1 get_AllScreens
		$a_81_3 = {53 63 72 65 65 6e 54 6f 43 6c 69 65 6e 74 } //1 ScreenToClient
		$a_81_4 = {56 69 64 65 6f 43 61 70 74 75 72 65 44 65 76 69 63 65 } //1 VideoCaptureDevice
		$a_81_5 = {49 73 4c 6f 67 67 69 6e 67 } //1 IsLogging
		$a_81_6 = {43 6f 6d 70 75 74 65 72 49 6e 66 6f } //1 ComputerInfo
	condition:
		((#a_01_0  & 1)*100+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=106
 
}