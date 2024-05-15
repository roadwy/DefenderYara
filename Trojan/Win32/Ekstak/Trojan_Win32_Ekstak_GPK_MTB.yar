
rule Trojan_Win32_Ekstak_GPK_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 04 00 "
		
	strings :
		$a_03_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 90 01 03 00 90 01 03 00 00 ca 0a 00 67 f5 08 f4 90 00 } //04 00 
		$a_03_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 90 01 03 00 90 01 03 00 00 96 0a 00 aa ed 2d a8 90 00 } //04 00 
		$a_03_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 90 01 03 00 90 01 03 00 00 d2 0a 00 de 63 3f a6 c5 f4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}