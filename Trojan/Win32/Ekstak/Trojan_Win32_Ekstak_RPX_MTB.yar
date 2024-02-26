
rule Trojan_Win32_Ekstak_RPX_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {e4 f8 69 00 06 5d 66 00 00 be 0a 00 d4 bd 14 99 bc 16 66 00 00 d4 00 00 49 bd be 36 } //01 00 
		$a_01_1 = {4e 00 65 00 74 00 53 00 63 00 68 00 65 00 6d 00 65 00 43 00 41 00 42 00 } //00 00  NetSchemeCAB
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {91 51 69 00 b3 b5 65 00 00 be 0a 00 d4 bd 14 99 54 6f 65 00 00 d4 00 00 dd 9a ed ec } //0a 00 
		$a_01_1 = {c0 0c 69 00 e2 70 65 00 00 be 0a 00 d4 bd 14 99 7a 2a 65 00 00 d4 00 00 62 4e 54 08 } //01 00 
		$a_01_2 = {4e 00 65 00 74 00 53 00 63 00 68 00 65 00 6d 00 65 00 43 00 41 00 42 00 } //00 00  NetSchemeCAB
	condition:
		any of ($a_*)
 
}