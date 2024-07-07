
rule Trojan_Win32_Dridex_SE_MTB{
	meta:
		description = "Trojan:Win32/Dridex.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 "
		
	strings :
		$a_80_0 = {53 65 74 55 72 6c 43 61 63 68 65 45 6e 74 72 79 49 6e 66 6f 57 } //SetUrlCacheEntryInfoW  3
		$a_80_1 = {45 53 20 41 50 50 20 45 5f } //ES APP E_  3
		$a_80_2 = {65 6c 66 20 45 58 } //elf EX  3
		$a_80_3 = {4d 61 70 56 69 72 74 75 61 6c 4b 65 79 41 } //MapVirtualKeyA  3
		$a_80_4 = {4c 6f 61 64 4b 65 79 62 6f 61 72 64 4c 61 79 6f 75 74 41 } //LoadKeyboardLayoutA  3
		$a_80_5 = {53 77 69 74 63 68 54 6f 54 68 69 73 57 69 6e 64 6f 77 } //SwitchToThisWindow  3
		$a_80_6 = {53 43 61 72 64 44 69 73 63 6f 6e 6e 65 63 74 } //SCardDisconnect  3
		$a_80_7 = {53 65 74 75 70 44 69 44 65 6c 65 74 65 44 65 76 69 63 65 49 6e 74 65 72 66 61 63 65 44 61 74 61 } //SetupDiDeleteDeviceInterfaceData  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3) >=24
 
}