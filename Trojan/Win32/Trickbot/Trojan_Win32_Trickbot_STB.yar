
rule Trojan_Win32_Trickbot_STB{
	meta:
		description = "Trojan:Win32/Trickbot.STB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {10 36 34 00 00 4c 64 72 41 63 63 65 73 73 52 65 73 6f 75 72 63 65 00 00 00 4c 64 72 46 69 6e 64 52 65 73 6f 75 72 63 65 5f 55 00 00 00 6e 74 64 6c 6c 2e 64 6c 6c 00 00 00 43 3a 5c 57 69 6e 64 6f 77 73 5c 6e 6f 74 65 70 61 64 2e 65 78 65 00 } //01 00 
		$a_01_1 = {53 68 6f 77 54 69 6d 65 36 34 2e 65 78 65 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00  桓睯楔敭㐶攮數䐀汬敒楧瑳牥敓癲牥
	condition:
		any of ($a_*)
 
}