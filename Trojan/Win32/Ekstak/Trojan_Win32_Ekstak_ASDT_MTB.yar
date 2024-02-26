
rule Trojan_Win32_Ekstak_ASDT_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 7f 05 69 00 a1 69 65 00 00 be } //05 00 
		$a_01_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 18 bd 68 00 3a 21 65 00 00 be 0a 00 d4 bd 14 99 } //05 00 
		$a_01_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 8e bb 68 00 b0 1f 65 00 00 be 0a 00 d4 bd 14 99 } //00 00 
	condition:
		any of ($a_*)
 
}