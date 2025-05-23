
rule TrojanSpy_Win32_Usteal_D{
	meta:
		description = "TrojanSpy:Win32/Usteal.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_01_0 = {55 46 52 20 53 74 65 61 6c 65 72 20 52 65 70 6f 72 74 20 5b 20 25 73 20 5d } //1 UFR Stealer Report [ %s ]
		$a_01_1 = {72 65 70 6f 72 74 5f 00 2e 62 69 6e 00 4e 4f 5f 50 57 44 53 5f } //1
		$a_01_2 = {46 54 50 00 2a 00 46 69 6c 65 2d 50 61 74 68 73 2e 74 78 74 00 46 69 6c 65 73 2d 41 72 65 2d 43 6f 70 69 65 64 2e 74 78 74 00 41 50 50 44 41 54 41 00 55 46 52 } //1
		$a_02_3 = {66 74 70 2e 66 72 6f 6e 74 2e 72 75 [0-10] 6d 61 6a 65 73 74 69 63 6b 31 32 [0-10] 6d 6a 31 32 67 70 33 32 30 } //1
		$a_03_4 = {68 ff 00 00 00 ff 75 fc 6a 01 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 15 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 0b c0 75 11 ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? e9 b2 ?? ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_02_3  & 1)*1+(#a_03_4  & 1)*1) >=2
 
}