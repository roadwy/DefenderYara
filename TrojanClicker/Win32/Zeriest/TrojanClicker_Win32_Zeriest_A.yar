
rule TrojanClicker_Win32_Zeriest_A{
	meta:
		description = "TrojanClicker:Win32/Zeriest.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 2e 6c 6e 6b 00 [0-10] 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 00 [0-10] 50 52 4f 47 52 41 4d 46 49 4c 45 53 00 [0-10] 5c 73 79 73 74 65 6d 5c 33 36 30 2e 69 63 6f 00 [0-10] 43 4f 4d 4d 4f 4e 50 52 4f 47 52 41 4d 46 49 4c 45 53 } //1
		$a_03_1 = {2e 31 6e 6b 00 [0-10] 5c 73 79 73 74 65 6d 5c 74 61 6f 62 61 6f 2e 69 63 6f 00 [0-25] 68 } //1
		$a_03_2 = {54 42 46 49 4c 45 53 00 [0-10] 2e 75 72 31 00 [0-10] 49 45 46 49 4c 45 53 00 [0-10] 2e 69 65 00 [0-10] 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 2e 69 65 00 [0-20] 2e 75 72 31 00 [0-20] 2e 31 6e 6b 00 [0-10] 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 51 75 69 63 6b 20 4c 61 75 6e 63 68 5c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}