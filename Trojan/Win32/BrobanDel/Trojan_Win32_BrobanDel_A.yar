
rule Trojan_Win32_BrobanDel_A{
	meta:
		description = "Trojan:Win32/BrobanDel.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 75 6e 4c 65 67 61 63 79 43 50 4c 45 6c 65 76 61 74 65 64 2e 65 78 65 20 53 68 65 6c 6c 33 32 2e 64 6c 6c 2c 43 6f 6e 74 72 6f 6c 5f 52 75 6e 44 4c 4c } //1 RunLegacyCPLElevated.exe Shell32.dll,Control_RunDLL
		$a_01_1 = {65 78 74 65 6e 73 69 6f 6e 73 2e 73 68 6f 77 6e 53 65 6c 65 63 74 69 6f 6e 55 49 } //1 extensions.shownSelectionUI
		$a_01_2 = {65 78 74 65 6e 73 69 6f 6e 73 2e 61 75 74 6f 44 69 73 61 62 6c 65 53 63 6f 70 65 73 } //1 extensions.autoDisableScopes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}