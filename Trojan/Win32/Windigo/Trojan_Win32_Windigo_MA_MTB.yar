
rule Trojan_Win32_Windigo_MA_MTB{
	meta:
		description = "Trojan:Win32/Windigo.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {45 75 7a 42 33 4b 69 70 47 73 73 61 62 42 6f 38 } //05 00 
		$a_01_1 = {76 7a 79 37 57 79 53 36 58 6f 31 63 55 7a 39 50 58 6d 2f 35 36 47 30 78 45 6f 39 75 } //05 00 
		$a_01_2 = {ff 35 fb 05 0f 86 90 05 10 86 64 6e 6c 8b 4c 24 68 85 eb de 3e fb c0 0f 84 e1 03 24 86 18 89 1e } //01 00 
		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00 
		$a_01_4 = {55 50 58 30 } //01 00 
		$a_01_5 = {55 50 58 31 } //00 00 
	condition:
		any of ($a_*)
 
}