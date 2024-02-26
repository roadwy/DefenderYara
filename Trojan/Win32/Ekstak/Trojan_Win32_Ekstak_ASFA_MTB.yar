
rule Trojan_Win32_Ekstak_ASFA_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 90 01 03 00 90 01 03 00 00 c4 0a 00 7a f3 50 90 00 } //05 00 
		$a_03_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 90 01 03 00 90 01 03 00 00 c4 0a 00 aa 70 97 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}