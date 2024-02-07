
rule Trojan_Win32_NSISInject_RPG_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {55 72 62 61 6e 69 74 65 74 65 6e 73 } //01 00  Urbanitetens
		$a_81_1 = {47 67 65 6c 65 64 65 72 6e 65 2e 41 76 6c 32 34 30 } //01 00  Ggelederne.Avl240
		$a_81_2 = {53 6f 66 74 77 61 72 65 5c 43 6f 65 72 63 69 76 65 5c 4c 6f 72 61 72 69 75 73 5c 48 6f 69 73 74 65 64 } //01 00  Software\Coercive\Lorarius\Hoisted
		$a_81_3 = {42 69 6f 74 65 6b 6e 69 6b 65 72 65 72 6e 65 73 2e 4a 75 6e } //00 00  Bioteknikerernes.Jun
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RPG_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 65 72 72 69 6d 61 67 6e 65 74 69 63 61 6c 6c 79 } //01 00  Ferrimagnetically
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 44 69 73 6f 72 64 65 72 65 72 5c 4d 65 64 6c 65 6d 73 6c 69 73 74 65 72 5c 50 65 61 73 63 6f 64 } //01 00  Software\Disorderer\Medlemslister\Peascod
		$a_01_2 = {42 61 6e 6a 6f 73 2e 42 65 76 } //01 00  Banjos.Bev
		$a_01_3 = {46 6f 6c 64 6e 69 6e 67 73 73 74 6e 69 6e 67 65 72 6e 65 } //01 00  Foldningsstningerne
		$a_01_4 = {6f 75 74 73 70 65 6e 74 2e 52 6f 74 } //00 00  outspent.Rot
	condition:
		any of ($a_*)
 
}