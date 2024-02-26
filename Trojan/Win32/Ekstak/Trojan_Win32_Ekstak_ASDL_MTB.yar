
rule Trojan_Win32_Ekstak_ASDL_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 34 10 65 00 6a 00 8d 4c 24 10 6a 01 51 c7 44 24 18 0c 00 00 00 89 74 24 1c c7 44 24 20 00 00 00 00 ff 15 90 02 03 00 a3 74 1d 65 00 5e 83 c4 10 c3 90 00 } //01 00 
		$a_03_1 = {68 34 10 65 00 6a 00 8d 44 24 18 6a 01 50 c7 44 24 20 0c 00 00 00 89 74 24 24 c7 44 24 28 00 00 00 00 ff 15 90 02 03 00 5f a3 74 1d 65 00 5e 83 c4 14 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}