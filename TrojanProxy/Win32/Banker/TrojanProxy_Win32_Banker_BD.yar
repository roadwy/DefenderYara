
rule TrojanProxy_Win32_Banker_BD{
	meta:
		description = "TrojanProxy:Win32/Banker.BD,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 07 00 00 "
		
	strings :
		$a_03_0 = {72 65 6d 65 74 65 6e 74 65 3d 70 63 77 40 70 63 77 2e 63 6f 6d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 64 65 73 74 69 6e 61 74 61 72 69 6f 3d 00 } //1
		$a_03_1 = {63 68 72 6f 6d 65 2e 65 78 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 69 72 65 66 6f 78 2e 65 78 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //1
		$a_03_2 = {5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 75 74 6f 43 6f 6e 66 69 67 55 52 4c } //1
		$a_03_3 = {5c 5a 6f 6e 65 4d 61 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 75 74 6f 44 65 74 65 63 74 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 64 76 61 6e 63 65 64 } //1
		$a_03_4 = {2e 70 61 63 00 [0-03] ff ff ff ff 3b 00 00 00 53 6f 66 74 77 61 72 65 5c 50 6f 6c 69 63 69 65 73 5c } //1
		$a_01_5 = {50 72 6f 6a 65 63 74 33 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 00 } //1
		$a_03_6 = {66 69 72 65 66 6f 78 2e 65 78 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? 63 68 72 6f 6d 65 2e 65 78 65 00 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*2) >=4
 
}