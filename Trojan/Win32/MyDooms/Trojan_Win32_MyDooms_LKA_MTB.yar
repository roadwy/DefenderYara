
rule Trojan_Win32_MyDooms_LKA_MTB{
	meta:
		description = "Trojan:Win32/MyDooms.LKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {7e 0f 8b 13 8b 43 04 89 04 1a 83 c3 08 ff 09 eb ec } //01 00 
		$a_01_1 = {81 2a 6a 17 62 3c eb 02 } //00 00 
	condition:
		any of ($a_*)
 
}