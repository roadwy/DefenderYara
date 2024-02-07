
rule Trojan_Win32_Nebuler_gen_B{
	meta:
		description = "Trojan:Win32/Nebuler.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 6f 6f 6b 45 78 } //01 00  HookEx
		$a_01_1 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 73 55 73 65 72 41 } //01 00  CreateProcessAsUserA
		$a_01_2 = {52 61 73 45 6e 75 6d 44 65 76 69 63 65 73 41 } //01 00  RasEnumDevicesA
		$a_01_3 = {25 64 26 63 6d 64 69 64 3d 25 64 } //01 00  %d&cmdid=%d
		$a_01_4 = {45 76 74 53 68 75 74 64 6f 77 6e } //01 00  EvtShutdown
		$a_01_5 = {45 76 74 53 74 61 72 74 75 70 } //01 00  EvtStartup
		$a_01_6 = {64 65 6c 20 22 25 73 22 } //01 00  del "%s"
		$a_01_7 = {53 48 47 65 74 56 61 6c 75 65 41 } //01 00  SHGetValueA
		$a_01_8 = {53 48 44 65 6c 65 74 65 56 61 6c 75 65 41 } //01 00  SHDeleteValueA
		$a_01_9 = {47 65 74 41 64 61 70 74 65 72 73 49 6e 66 6f } //01 00  GetAdaptersInfo
		$a_01_10 = {69 70 68 6c 70 61 70 69 2e 64 6c 6c } //00 00  iphlpapi.dll
	condition:
		any of ($a_*)
 
}