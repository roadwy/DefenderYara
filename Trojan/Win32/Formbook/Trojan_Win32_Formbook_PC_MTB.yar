
rule Trojan_Win32_Formbook_PC_MTB{
	meta:
		description = "Trojan:Win32/Formbook.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8d 78 01 8a 10 40 84 d2 75 90 01 01 2b c7 8b f8 33 d2 8b c1 f7 f7 41 8a 92 90 01 03 00 30 54 31 ff 3b cb 72 90 00 } //01 00 
		$a_00_1 = {47 00 6f 00 6c 00 64 00 65 00 72 00 6e 00 43 00 72 00 79 00 70 00 74 00 65 00 72 00 } //00 00  GoldernCrypter
	condition:
		any of ($a_*)
 
}