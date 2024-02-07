
rule Trojan_Win32_Iflar_gen_C{
	meta:
		description = "Trojan:Win32/Iflar.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 03 00 "
		
	strings :
		$a_03_0 = {50 8d 45 f0 68 90 01 03 00 50 e8 90 01 02 ff ff 8b 5d f0 83 c4 14 53 57 6a 01 57 ff 15 90 01 03 00 83 f8 ff 89 86 90 01 01 02 00 00 0f 95 c0 88 86 90 01 01 02 00 00 90 00 } //01 00 
		$a_01_1 = {41 43 55 45 49 4c 4c 49 52 4d 49 58 00 } //01 00 
		$a_01_2 = {69 66 75 63 6b 6c 61 72 67 65 25 64 00 } //01 00 
		$a_01_3 = {4e 76 63 68 6f 73 74 00 } //01 00  癎档獯t
		$a_01_4 = {53 79 73 74 65 6d 44 65 6c 65 74 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}