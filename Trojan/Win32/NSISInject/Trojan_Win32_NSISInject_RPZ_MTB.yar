
rule Trojan_Win32_NSISInject_RPZ_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 61 6c 76 74 72 65 64 73 61 61 72 69 67 65 5c 73 75 6e 6e 69 74 74 65 6e 73 5c 52 67 74 65 6e 64 65 } //01 00  Halvtredsaarige\sunnittens\Rgtende
		$a_01_1 = {53 6c 61 76 65 6e 73 2e 73 75 62 } //01 00  Slavens.sub
		$a_01_2 = {4b 6f 6d 6d 69 73 73 69 6f 6e 65 72 65 31 39 38 } //01 00  Kommissionere198
		$a_01_3 = {4d 61 72 6d 6f 72 68 76 69 64 74 2e 53 70 72 } //01 00  Marmorhvidt.Spr
		$a_01_4 = {44 69 70 68 65 6e 6f 78 79 6c 61 74 65 2e 4e 61 65 } //00 00  Diphenoxylate.Nae
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RPZ_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 00 6c 00 6f 00 61 00 6b 00 65 00 72 00 69 00 6e 00 67 00 73 00 62 00 65 00 73 00 6c 00 75 00 74 00 6e 00 69 00 6e 00 67 00 73 00 } //01 00  kloakeringsbeslutnings
		$a_01_1 = {49 00 6e 00 64 00 6c 00 6f 00 64 00 73 00 65 00 64 00 65 00 73 00 31 00 39 00 36 00 } //01 00  Indlodsedes196
		$a_01_2 = {6f 00 70 00 70 00 6f 00 73 00 69 00 74 00 69 00 6f 00 6e 00 61 00 6c 00 2e 00 53 00 68 00 65 00 } //01 00  oppositional.She
		$a_01_3 = {64 00 69 00 76 00 65 00 72 00 73 00 69 00 66 00 6f 00 72 00 6d 00 5c 00 72 00 65 00 73 00 75 00 62 00 6c 00 69 00 6d 00 61 00 74 00 69 00 6e 00 67 00 } //01 00  diversiform\resublimating
		$a_01_4 = {6f 00 70 00 62 00 79 00 67 00 6e 00 69 00 6e 00 67 00 73 00 66 00 61 00 73 00 65 00 72 00 73 00 } //00 00  opbygningsfasers
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RPZ_MTB_3{
	meta:
		description = "Trojan:Win32/NSISInject.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 00 69 00 6c 00 6d 00 76 00 69 00 64 00 65 00 6e 00 73 00 6b 00 61 00 62 00 73 00 5c 00 4c 00 69 00 6d 00 62 00 6d 00 65 00 61 00 6c 00 } //01 00  Filmvidenskabs\Limbmeal
		$a_01_1 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 55 00 70 00 63 00 6c 00 69 00 6d 00 62 00 65 00 72 00 31 00 38 00 33 00 } //01 00  Software\Upclimber183
		$a_01_2 = {49 00 72 00 72 00 69 00 64 00 65 00 2e 00 4d 00 61 00 6e 00 } //01 00  Irride.Man
		$a_01_3 = {4d 00 69 00 6b 00 72 00 6f 00 6f 00 72 00 67 00 61 00 6e 00 69 00 73 00 6d 00 65 00 } //01 00  Mikroorganisme
		$a_01_4 = {49 00 6e 00 64 00 66 00 6c 00 64 00 65 00 72 00 5c 00 41 00 66 00 72 00 6f 00 64 00 69 00 73 00 69 00 61 00 6b 00 61 00 73 00 5c 00 50 00 75 00 72 00 6b 00 65 00 6e 00 2e 00 69 00 6e 00 69 00 } //00 00  Indflder\Afrodisiakas\Purken.ini
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RPZ_MTB_4{
	meta:
		description = "Trojan:Win32/NSISInject.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 00 6e 00 64 00 75 00 73 00 74 00 72 00 69 00 66 00 65 00 72 00 69 00 65 00 6e 00 73 00 2e 00 43 00 61 00 72 00 } //01 00  Industriferiens.Car
		$a_01_1 = {53 00 61 00 6e 00 6a 00 61 00 6b 00 73 00 68 00 69 00 70 00 5c 00 45 00 78 00 74 00 72 00 61 00 76 00 61 00 67 00 61 00 6e 00 63 00 65 00 73 00 5c 00 4d 00 75 00 6c 00 64 00 76 00 61 00 72 00 70 00 65 00 73 00 6b 00 75 00 64 00 } //01 00  Sanjakship\Extravagances\Muldvarpeskud
		$a_01_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 41 00 6e 00 74 00 69 00 6d 00 61 00 6e 00 69 00 61 00 63 00 61 00 6c 00 5c 00 42 00 6f 00 67 00 6c 00 61 00 64 00 65 00 70 00 72 00 69 00 73 00 65 00 6e 00 73 00 } //01 00  Software\Antimaniacal\Bogladeprisens
		$a_01_3 = {46 00 69 00 62 00 72 00 69 00 6c 00 6c 00 61 00 74 00 65 00 64 00 32 00 35 00 32 00 } //01 00  Fibrillated252
		$a_01_4 = {41 00 6d 00 70 00 65 00 72 00 65 00 2e 00 69 00 6e 00 69 00 } //00 00  Ampere.ini
	condition:
		any of ($a_*)
 
}