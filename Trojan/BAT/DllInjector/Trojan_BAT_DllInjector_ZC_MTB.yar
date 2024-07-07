
rule Trojan_BAT_DllInjector_ZC_MTB{
	meta:
		description = "Trojan:BAT/DllInjector.ZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 08 00 0d 00 00 "
		
	strings :
		$a_00_0 = {4c 6f 61 64 49 6d 61 67 65 54 6f 4d 65 6d 6f 72 79 } //1 LoadImageToMemory
		$a_00_1 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 ReadProcessMemory
		$a_00_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_00_3 = {49 00 6e 00 6a 00 65 00 63 00 74 00 65 00 64 00 21 00 } //1 Injected!
		$a_03_4 = {67 69 67 63 61 70 61 73 74 65 5c 6c 6f 61 64 65 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 90 02 20 2e 70 64 62 90 00 } //1
		$a_00_5 = {73 65 74 5f 41 73 79 6e 63 49 6e 6a 65 63 74 69 6f 6e } //1 set_AsyncInjection
		$a_00_6 = {4d 61 6e 75 61 6c 4d 61 70 49 6e 6a 65 63 74 6f 72 } //1 ManualMapInjector
		$a_00_7 = {67 65 74 5f 41 73 79 6e 63 49 6e 6a 65 63 74 69 6f 6e } //1 get_AsyncInjection
		$a_00_8 = {4d 61 6e 75 61 6c 4d 61 70 49 6e 6a 65 63 74 69 6f 6e 2e 49 6e 6a 65 63 74 69 6f 6e 2e 54 79 70 65 73 } //1 ManualMapInjection.Injection.Types
		$a_00_9 = {41 6e 74 69 46 69 64 64 6c 65 72 } //1 AntiFiddler
		$a_00_10 = {43 00 6f 00 70 00 79 00 20 00 48 00 57 00 49 00 44 00 } //1 Copy HWID
		$a_00_11 = {63 00 73 00 67 00 6f 00 } //1 csgo
		$a_00_12 = {53 00 74 00 61 00 62 00 6c 00 65 00 } //1 Stable
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_03_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1) >=8
 
}