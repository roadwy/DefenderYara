
rule Trojan_BAT_Zusy_XN_MTB{
	meta:
		description = "Trojan:BAT/Zusy.XN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 "
		
	strings :
		$a_03_0 = {72 2b 02 00 70 0a 06 17 8d ?? 00 00 01 0c 08 16 1f 2c 9d 08 6f ?? 00 00 0a 7e ?? 00 00 04 2d 11 14 fe 06 18 00 00 06 } //2
		$a_81_1 = {47 6c 6f 62 61 6c 5c 4d 61 73 6f 6e 53 65 72 76 69 63 65 49 6e 73 74 61 6e 63 65 } //2 Global\MasonServiceInstance
		$a_81_2 = {48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 57 69 6e 64 6f 77 73 20 45 72 72 6f 72 20 52 65 70 6f 72 74 69 6e 67 } //1 HKEY_CURRENT_USER\Software\Microsoft\Windows\Windows Error Reporting
		$a_81_3 = {57 45 52 5f 46 41 55 4c 54 5f 52 45 50 4f 52 54 49 4e 47 } //1 WER_FAULT_REPORTING
		$a_81_4 = {44 69 73 61 62 6c 65 57 65 72 } //1 DisableWer
		$a_81_5 = {4c 6f 61 64 53 68 65 6c 6c 63 6f 64 65 } //1 LoadShellcode
		$a_81_6 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_81_7 = {43 72 65 61 74 65 54 68 72 65 61 64 } //1 CreateThread
	condition:
		((#a_03_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=10
 
}