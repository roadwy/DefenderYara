
rule Trojan_Win32_Vatet_SZS{
	meta:
		description = "Trojan:Win32/Vatet.SZS,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 07 00 00 0a 00 "
		
	strings :
		$a_80_0 = {52 41 49 4e 4d 45 54 45 52 2e 44 4c 4c } //RAINMETER.DLL  0a 00 
		$a_80_1 = {53 6f 66 74 77 61 72 65 5c 52 61 69 6e 6d 65 74 65 72 } //Software\Rainmeter  0a 00 
		$a_80_2 = {52 61 69 6e 6d 65 74 65 72 20 64 65 73 6b 74 6f 70 20 63 75 73 74 6f 6d 69 7a 61 74 69 6f 6e 20 74 6f 6f 6c } //Rainmeter desktop customization tool  0a 00 
		$a_03_3 = {40 3b c3 72 90 09 04 00 80 90 01 02 fe 90 00 } //01 00 
		$a_03_4 = {5c 5c 31 30 2e 90 02 03 2e 90 02 03 2e 90 02 03 5c 90 00 } //01 00 
		$a_03_5 = {5c 5c 31 37 32 2e 90 02 03 2e 90 02 03 2e 90 02 03 5c 90 00 } //01 00 
		$a_03_6 = {5c 5c 31 39 32 2e 31 36 38 2e 90 02 03 2e 90 02 03 5c 90 00 } //00 00 
		$a_00_7 = {5d 04 00 00 90 25 04 80 5c 3e 00 00 91 25 04 80 00 00 01 00 04 00 28 00 54 72 6f 6a 61 6e 44 } //6f 77 
	condition:
		any of ($a_*)
 
}