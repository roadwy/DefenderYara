
rule Trojan_Win32_Ridok_A{
	meta:
		description = "Trojan:Win32/Ridok.A,SIGNATURE_TYPE_PEHSTR,0d 00 06 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {67 62 6f 74 2e 70 68 70 3f 63 6f 75 6e 74 72 79 3d 00 } //05 00  执瑯瀮灨挿畯瑮祲=
		$a_01_1 = {39 64 65 64 61 6c } //01 00  9dedal
		$a_01_2 = {61 63 63 65 70 74 2d 6c 61 6e 67 75 61 67 65 3a 20 72 75 } //01 00  accept-language: ru
		$a_01_3 = {79 61 6e 64 65 78 2e 72 75 } //01 00  yandex.ru
		$a_01_4 = {67 6f 6f 67 6c 65 62 6f 74 } //00 00  googlebot
	condition:
		any of ($a_*)
 
}