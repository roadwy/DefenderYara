
rule TrojanProxy_Win32_Donbot_A{
	meta:
		description = "TrojanProxy:Win32/Donbot.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 5c 73 79 73 74 65 6d 33 32 5c 6d 73 76 63 72 74 32 2e 64 6c 6c 00 72 00 25 73 5c 73 79 73 74 65 6d 33 32 5c 73 79 73 6d 67 72 2e 65 78 65 } //1
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 4d 69 63 72 6f 73 6f 66 74 28 52 29 20 53 79 73 74 65 6d 20 4d 61 6e 61 67 65 72 } //1
		$a_01_2 = {43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 54 63 70 69 70 5c 50 61 72 61 6d 65 74 65 72 73 00 54 63 70 54 69 6d 65 64 57 61 69 74 44 65 6c 61 79 00 4d 61 78 55 73 65 72 50 6f 72 74 00 25 30 32 78 00 75 70 64 61 74 65 } //1
		$a_03_3 = {48 45 4c 4f 20 25 73 ?? ?? ?? 4d 41 49 4c 20 46 52 4f 4d 3a 3c 25 73 3e ?? ?? ?? 52 43 50 54 20 54 4f 3a 3c 25 73 3e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}