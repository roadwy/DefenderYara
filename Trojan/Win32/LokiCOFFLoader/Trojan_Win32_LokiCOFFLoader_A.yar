
rule Trojan_Win32_LokiCOFFLoader_A{
	meta:
		description = "Trojan:Win32/LokiCOFFLoader.A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 03 00 09 00 00 "
		
	strings :
		$a_81_0 = {43 4f 46 46 4c 6f 61 64 65 72 } //2 COFFLoader
		$a_81_1 = {72 75 6e 43 4f 46 46 } //2 runCOFF
		$a_81_2 = {62 65 61 63 6f 6e 5f 63 6f 6d 70 61 74 69 62 69 6c 69 74 79 } //1 beacon_compatibility
		$a_81_3 = {67 6f 5f 63 61 6c 6c 62 61 63 6b } //1 go_callback
		$a_81_4 = {42 65 61 63 6f 6e 44 61 74 61 50 61 72 73 65 } //1 BeaconDataParse
		$a_81_5 = {42 65 61 63 6f 6e 50 72 69 6e 74 66 } //1 BeaconPrintf
		$a_81_6 = {42 65 61 63 6f 6e 4f 75 74 70 75 74 } //1 BeaconOutput
		$a_81_7 = {42 65 61 63 6f 6e 46 6f 72 6d 61 74 41 6c 6c 6f 63 } //1 BeaconFormatAlloc
		$a_81_8 = {42 65 61 63 6f 6e 46 6f 72 6d 61 74 46 72 65 65 } //1 BeaconFormatFree
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=3
 
}