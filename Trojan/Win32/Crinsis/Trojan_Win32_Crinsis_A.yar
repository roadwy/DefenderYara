
rule Trojan_Win32_Crinsis_A{
	meta:
		description = "Trojan:Win32/Crinsis.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 45 e8 00 00 00 00 c7 85 90 01 02 ff ff 00 00 00 00 c7 85 90 01 02 ff ff 7a fc ff 7f 0f be 05 90 01 02 00 10 0f be 0d 90 01 02 00 10 90 00 } //01 00 
		$a_03_1 = {86 03 00 00 0f bf 0d 90 01 02 00 10 0f bf 15 90 01 02 00 10 2b ca 89 90 02 06 0f be 05 90 01 02 00 10 8b 0d 90 01 02 00 10 03 c8 89 90 00 } //01 00 
		$a_03_2 = {b9 e1 00 00 00 33 c0 8d bd 90 01 02 ff ff f3 ab aa 90 00 } //01 00 
		$a_03_3 = {99 f7 f9 0f bf 15 90 01 01 81 00 10 88 84 15 90 01 02 ff ff 90 00 } //01 00 
		$a_03_4 = {b9 06 00 00 00 33 c0 8d bd 90 01 02 ff ff f3 ab c6 85 90 01 02 ff ff 00 b9 06 00 00 00 33 c0 8d bd 90 01 02 ff ff f3 ab b9 4b 00 00 00 33 c0 8d bd 90 01 02 ff ff f3 ab 0f 90 00 } //00 00 
		$a_00_5 = {5d 04 00 } //00 62 
	condition:
		any of ($a_*)
 
}