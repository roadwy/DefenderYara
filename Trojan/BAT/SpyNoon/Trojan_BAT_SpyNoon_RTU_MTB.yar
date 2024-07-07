
rule Trojan_BAT_SpyNoon_RTU_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.RTU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_01_0 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_1 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_01_2 = {67 65 74 5f 41 6c 6c 6f 77 4f 6e 6c 79 46 69 70 73 41 6c 67 6f 72 69 74 68 6d 73 } //1 get_AllowOnlyFipsAlgorithms
		$a_01_3 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //1 SetWindowsHookEx
		$a_01_4 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //1 UnhookWindowsHookEx
		$a_01_5 = {47 65 74 43 75 72 73 6f 72 49 6e 66 6f } //1 GetCursorInfo
		$a_01_6 = {24 65 32 61 63 62 34 36 37 2d 37 32 65 65 2d 34 65 39 62 2d 39 35 30 64 2d 65 32 63 66 64 62 38 61 34 38 64 31 } //10 $e2acb467-72ee-4e9b-950d-e2cfdb8a48d1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*10) >=16
 
}