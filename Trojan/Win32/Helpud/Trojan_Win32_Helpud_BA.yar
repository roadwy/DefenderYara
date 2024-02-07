
rule Trojan_Win32_Helpud_BA{
	meta:
		description = "Trojan:Win32/Helpud.BA,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {64 6c 6c 66 69 6c 65 00 6d 6b 73 48 6f 6f 6b 00 6d 74 7a 48 6f 6f 6b 00 } //01 00  汤晬汩e歭䡳潯k瑭䡺潯k
		$a_01_1 = {69 66 20 65 78 69 73 74 20 00 00 00 67 6f 74 6f 20 } //01 00 
		$a_01_2 = {41 56 50 2e 54 72 61 66 66 69 63 4d 6f 6e 43 6f 6e 6e 65 63 74 69 6f 6e 54 65 72 6d 00 } //01 00 
		$a_01_3 = {4b 56 58 50 5f 4d 6f 6e 69 74 6f 72 00 } //01 00 
		$a_01_4 = {00 79 6d 2e 64 6c 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}