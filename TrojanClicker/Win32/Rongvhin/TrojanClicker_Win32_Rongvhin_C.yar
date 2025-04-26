
rule TrojanClicker_Win32_Rongvhin_C{
	meta:
		description = "TrojanClicker:Win32/Rongvhin.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 7e 48 74 3f 48 75 2a 8b 7c 24 14 56 6a 02 68 04 02 00 00 57 e8 } //1
		$a_01_1 = {41 50 49 2d 47 75 69 64 65 20 74 65 73 74 20 70 72 6f 67 72 61 6d } //1 API-Guide test program
		$a_01_2 = {4c 6f 61 64 69 6e 67 2c 50 6c 65 61 73 65 20 57 61 69 74 2e 2e 2e 2e 2e 2e 2e 2e } //1 Loading,Please Wait........
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}