
rule Trojan_Win32_Formbook_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Formbook.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 ab aa aa 2a f7 eb c1 fa 02 8b da c1 eb 1f 03 da 75 ed } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Formbook_RPZ_MTB_2{
	meta:
		description = "Trojan:Win32/Formbook.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 55 fc 83 c2 01 89 55 fc 81 7d fc 7f 17 00 00 7d 27 8b 45 fc 99 b9 0c 00 00 00 f7 f9 8b 45 ec 0f b6 0c 10 8b 55 f8 03 55 fc 0f b6 02 33 c1 8b 4d f8 03 4d fc 88 01 eb c7 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Formbook_RPZ_MTB_3{
	meta:
		description = "Trojan:Win32/Formbook.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 00 69 00 6d 00 65 00 6c 00 65 00 73 00 73 00 2e 00 48 00 6f 00 62 00 } //01 00  Rimeless.Hob
		$a_01_1 = {42 00 6c 00 6f 00 6d 00 6b 00 61 00 61 00 6c 00 73 00 68 00 6f 00 76 00 65 00 64 00 65 00 74 00 73 00 2e 00 61 00 6e 00 61 00 } //01 00  Blomkaalshovedets.ana
		$a_01_2 = {73 00 6b 00 75 00 66 00 66 00 65 00 6b 00 6f 00 6d 00 65 00 64 00 69 00 65 00 72 00 73 00 } //01 00  skuffekomediers
		$a_01_3 = {46 00 72 00 69 00 6e 00 67 00 65 00 62 00 61 00 61 00 64 00 } //01 00  Fringebaad
		$a_01_4 = {68 00 75 00 73 00 61 00 73 00 73 00 69 00 73 00 74 00 65 00 6e 00 74 00 2e 00 78 00 61 00 76 00 } //00 00  husassistent.xav
	condition:
		any of ($a_*)
 
}