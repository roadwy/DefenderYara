
rule Worm_Win32_Coinficon_A{
	meta:
		description = "Worm:Win32/Coinficon.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 04 00 "
		
	strings :
		$a_01_0 = {5c 4e 73 4d 69 6e 65 72 5c 49 4d 47 30 30 31 2e 65 78 65 } //04 00  \NsMiner\IMG001.exe
		$a_01_1 = {74 65 73 74 73 77 6f 72 6b 2e 72 75 2f 69 6e 66 6f 2e 7a 69 70 } //01 00  testswork.ru/info.zip
		$a_01_2 = {5c 69 6e 66 6f 2e 7a 69 70 } //02 00  \info.zip
		$a_01_3 = {c7 00 61 61 61 61 c7 40 04 61 61 61 61 c7 40 08 61 61 61 61 } //02 00 
		$a_03_4 = {c7 04 24 10 27 00 00 c7 85 90 01 02 ff ff ff ff ff ff e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}