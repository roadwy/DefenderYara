
rule Trojan_Win32_Fugrafa_KAA_MTB{
	meta:
		description = "Trojan:Win32/Fugrafa.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_80_0 = {51 62 76 54 68 65 63 48 65 4a } //QbvThecHeJ  01 00 
		$a_80_1 = {64 35 42 6c 65 73 73 65 64 59 69 73 6e 2e 74 66 73 70 69 72 69 74 34 73 68 65 2e 64 6a } //d5BlessedYisn.tfspirit4she.dj  01 00 
		$a_80_2 = {64 72 79 2e 66 69 74 62 72 6f 75 67 68 74 } //dry.fitbrought  00 00 
	condition:
		any of ($a_*)
 
}