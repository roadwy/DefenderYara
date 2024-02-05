
rule Trojan_Win32_Ekstak_HMQ_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.HMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 75 50 41 51 70 29 } //01 00 
		$a_01_1 = {5a 33 75 5d 65 39 4e 39 } //01 00 
		$a_01_2 = {63 59 7c 67 25 5b 7c 6f 27 7e } //01 00 
		$a_01_3 = {77 61 76 65 49 6e 41 64 64 42 75 66 66 65 72 } //01 00 
		$a_01_4 = {6b 4c 6f 61 64 65 72 4c 6f 63 6b } //00 00 
	condition:
		any of ($a_*)
 
}