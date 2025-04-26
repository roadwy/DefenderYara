
rule Trojan_Win32_Nebuler_gen_B{
	meta:
		description = "Trojan:Win32/Nebuler.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {48 6f 6f 6b 45 78 } //1 HookEx
		$a_01_1 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 73 55 73 65 72 41 } //1 CreateProcessAsUserA
		$a_01_2 = {52 61 73 45 6e 75 6d 44 65 76 69 63 65 73 41 } //1 RasEnumDevicesA
		$a_01_3 = {25 64 26 63 6d 64 69 64 3d 25 64 } //1 %d&cmdid=%d
		$a_01_4 = {45 76 74 53 68 75 74 64 6f 77 6e } //1 EvtShutdown
		$a_01_5 = {45 76 74 53 74 61 72 74 75 70 } //1 EvtStartup
		$a_01_6 = {64 65 6c 20 22 25 73 22 } //1 del "%s"
		$a_01_7 = {53 48 47 65 74 56 61 6c 75 65 41 } //1 SHGetValueA
		$a_01_8 = {53 48 44 65 6c 65 74 65 56 61 6c 75 65 41 } //1 SHDeleteValueA
		$a_01_9 = {47 65 74 41 64 61 70 74 65 72 73 49 6e 66 6f } //1 GetAdaptersInfo
		$a_01_10 = {69 70 68 6c 70 61 70 69 2e 64 6c 6c } //1 iphlpapi.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}