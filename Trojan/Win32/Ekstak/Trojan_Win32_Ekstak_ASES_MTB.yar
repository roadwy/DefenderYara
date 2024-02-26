
rule Trojan_Win32_Ekstak_ASES_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 90 02 03 00 90 02 03 00 00 be 0a 00 1e 08 3c 94 90 00 } //05 00 
		$a_03_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 90 02 03 00 90 02 03 00 00 be 0a 00 a0 a0 3d 6d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}