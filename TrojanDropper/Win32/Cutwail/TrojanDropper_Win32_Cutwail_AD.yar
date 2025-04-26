
rule TrojanDropper_Win32_Cutwail_AD{
	meta:
		description = "TrojanDropper:Win32/Cutwail.AD,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {6a 00 6a 00 6a 00 6a 00 68 80 24 08 9d } //1
		$a_01_1 = {5c 53 79 73 74 65 6d 33 32 5c 57 69 6e 4e 74 33 32 2e 64 6c 6c } //1 \System32\WinNt32.dll
		$a_01_2 = {53 74 61 72 74 00 00 00 54 79 70 65 00 00 00 00 41 73 79 6e 63 68 72 6f 6e 6f 75 73 00 00 00 00 49 6d 70 65 72 73 6f 6e 61 74 65 00 53 74 61 72 74 53 68 65 6c 6c 00 00 44 4c 4c 4e 61 6d 65 00 } //1
		$a_01_3 = {57 4c 45 76 65 6e 74 53 74 61 72 74 53 68 65 6c 6c } //1 WLEventStartShell
		$a_01_4 = {5c 5c 2e 5c 50 72 6f 74 32 00 00 00 52 75 6e } //1
		$a_01_5 = {53 74 61 72 74 53 65 72 76 69 63 65 41 } //1 StartServiceA
		$a_01_6 = {46 69 6e 64 52 65 73 6f 75 72 63 65 41 } //1 FindResourceA
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}