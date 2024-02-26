
rule Trojan_Win32_Ekstak_GPB_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 04 00 "
		
	strings :
		$a_03_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 90 01 03 00 90 01 03 00 00 c0 0a 00 0d 15 b6 76 90 00 } //04 00 
		$a_03_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 90 01 03 00 90 01 03 00 00 da 0a 00 73 5b 0d ca 90 00 } //04 00 
		$a_03_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 90 01 03 00 90 01 03 00 00 be 0a 00 d4 bd 14 99 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}