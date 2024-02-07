
rule Backdoor_Win32_Bazarloader_ST_{
	meta:
		description = "Backdoor:Win32/Bazarloader.ST!!Bazarloader.ST,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 64 31 2e 64 6c 6c 00 53 74 61 72 74 46 75 6e 63 00 } //01 00  摬⸱汤l瑓牡䙴湵c
		$a_01_1 = {77 73 32 5f 33 32 64 6c 6c 00 6e 74 64 6c 6c 2e 64 6c 6c 00 73 68 65 6c 6c 33 32 2e 64 6c 6c 00 77 69 6e 69 6e 65 74 2e 64 6c 6c 00 75 72 6c 6d 6f 6e 2e 64 6c 6c } //01 00 
		$a_01_2 = {48 8b 00 48 b9 00 00 00 00 ff ff ff ff 48 8b 40 30 48 23 c1 48 89 90 01 03 48 8b 90 01 03 8b 40 08 48 0b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Bazarloader_ST__2{
	meta:
		description = "Backdoor:Win32/Bazarloader.ST!!Bazarloader.ST,SIGNATURE_TYPE_ARHSTR_EXT,0d 00 0d 00 0b 00 00 0a 00 "
		
	strings :
		$a_03_0 = {e8 00 00 00 00 59 90 02 20 b9 05 00 00 00 90 02 0a 83 e4 f0 90 01 01 83 ec 30 c7 90 01 03 01 00 00 00 e8 05 00 00 00 90 00 } //03 00 
		$a_80_1 = {05 62 61 7a 61 72 00 } //bazar  03 00 
		$a_80_2 = {2e 62 61 7a 61 72 00 } //.bazar  03 00 
		$a_01_3 = {2e 64 6c 6c 00 53 74 61 72 74 46 75 6e 63 00 } //03 00 
		$a_01_4 = {77 73 32 5f 33 32 64 6c 6c 00 6e 74 64 6c 6c 2e 64 6c 6c 00 73 68 65 6c 6c 33 32 2e 64 6c 6c 00 77 69 6e 69 6e 65 74 2e 64 6c 6c 00 75 72 6c 6d 6f 6e 2e 64 6c 6c } //01 00 
		$a_01_5 = {b9 49 f7 02 78 90 02 08 e8 90 00 } //01 00 
		$a_01_6 = {b9 58 a4 53 e5 90 02 08 e8 90 00 } //01 00 
		$a_01_7 = {b9 10 e1 8a c3 90 02 08 e8 90 00 } //01 00 
		$a_01_8 = {b9 af b1 5c 94 90 02 08 e8 90 00 } //01 00 
		$a_01_9 = {b9 33 00 9e 95 90 02 08 e8 90 00 } //01 00 
		$a_01_10 = {48 8b 00 48 b9 00 00 00 00 ff ff ff ff 48 8b 40 30 48 23 c1 48 89 90 01 03 48 8b 90 01 03 8b 40 08 48 0b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}