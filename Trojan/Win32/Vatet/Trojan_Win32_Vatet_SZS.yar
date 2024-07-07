
rule Trojan_Win32_Vatet_SZS{
	meta:
		description = "Trojan:Win32/Vatet.SZS,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 07 00 00 "
		
	strings :
		$a_80_0 = {52 41 49 4e 4d 45 54 45 52 2e 44 4c 4c } //RAINMETER.DLL  10
		$a_80_1 = {53 6f 66 74 77 61 72 65 5c 52 61 69 6e 6d 65 74 65 72 } //Software\Rainmeter  10
		$a_80_2 = {52 61 69 6e 6d 65 74 65 72 20 64 65 73 6b 74 6f 70 20 63 75 73 74 6f 6d 69 7a 61 74 69 6f 6e 20 74 6f 6f 6c } //Rainmeter desktop customization tool  10
		$a_03_3 = {40 3b c3 72 90 09 04 00 80 90 01 02 fe 90 00 } //10
		$a_03_4 = {5c 5c 31 30 2e 90 02 03 2e 90 02 03 2e 90 02 03 5c 90 00 } //1
		$a_03_5 = {5c 5c 31 37 32 2e 90 02 03 2e 90 02 03 2e 90 02 03 5c 90 00 } //1
		$a_03_6 = {5c 5c 31 39 32 2e 31 36 38 2e 90 02 03 2e 90 02 03 5c 90 00 } //1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*10+(#a_03_3  & 1)*10+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1) >=41
 
}