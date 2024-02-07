
rule Trojan_Win32_Diamin_F{
	meta:
		description = "Trojan:Win32/Diamin.F,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 8d 45 f0 50 b9 90 01 04 ba 90 01 04 b8 90 01 04 e8 90 01 04 8b 45 f0 e8 90 01 04 50 6a 00 90 00 } //02 00 
		$a_02_1 = {6c 65 72 4d 90 02 10 44 69 61 90 00 } //02 00 
		$a_02_2 = {44 69 73 69 6e 73 74 61 6c 6c 61 2e 6c 6e 6b 90 02 10 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 90 00 } //01 00 
		$a_00_3 = {57 43 49 20 49 6e 74 65 72 6e 61 74 69 6f 6e 61 6c 20 72 61 74 65 73 20 61 70 70 6c 79 2e 20 4d 61 78 69 6d 75 6d 20 74 69 6d 65 3a 20 32 30 20 6d 69 6e 75 74 65 73 2e 20 43 4c 49 43 4b 20 4f 4e 20 59 45 53 20 54 4f 20 50 52 4f 43 45 45 44 21 } //0b 00  WCI International rates apply. Maximum time: 20 minutes. CLICK ON YES TO PROCEED!
		$a_02_4 = {6f 72 65 00 90 02 10 65 78 70 6c 90 02 20 6f 76 65 72 2e 20 57 6f 75 6c 64 20 79 6f 75 20 6c 69 6b 65 20 74 6f 20 63 6f 6e 6e 65 63 74 20 61 67 61 69 6e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}