
rule Trojan_Win32_Drixed_QS_MTB{
	meta:
		description = "Trojan:Win32/Drixed.QS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {26 54 68 7e 73 20 70 35 67 67 72 36 69 20 63 36 6a 6e 6f 3b 20 62 65 } //&Th~s p5ggr6i c6jno; be  3
		$a_80_1 = {27 62 72 61 2c 79 45 78 3f } //'bra,yEx?  3
		$a_80_2 = {57 54 53 47 65 74 41 63 74 69 76 65 43 6f 6e 73 6f 6c 65 53 65 73 73 69 6f 6e 49 64 } //WTSGetActiveConsoleSessionId  3
		$a_80_3 = {49 6e 53 65 6e 64 4d 65 73 73 61 67 65 45 78 } //InSendMessageEx  3
		$a_80_4 = {55 6e 72 65 67 69 73 74 65 72 48 6f 74 4b 65 79 } //UnregisterHotKey  3
		$a_80_5 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 73 55 73 65 72 57 } //CreateProcessAsUserW  3
		$a_80_6 = {49 6d 70 65 72 73 6f 6e 61 74 65 4c 6f 67 67 65 64 4f 6e 55 73 65 72 } //ImpersonateLoggedOnUser  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}