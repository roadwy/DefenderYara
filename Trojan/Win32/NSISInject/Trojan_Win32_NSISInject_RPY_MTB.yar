
rule Trojan_Win32_NSISInject_RPY_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 8d 95 90 01 01 fd ff ff 90 01 01 ff 55 d8 89 45 ec 83 7d ec ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 70 68 61 63 65 6c 75 73 5c 53 6e 6e 69 6b 65 72 } //01 00  sphacelus\Snniker
		$a_01_1 = {6b 72 79 70 74 65 72 69 6e 67 73 70 6f 6c 69 74 69 6b } //01 00  krypteringspolitik
		$a_01_2 = {74 69 70 70 65 6c 61 64 65 74 } //01 00  tippeladet
		$a_01_3 = {53 70 72 79 64 73 74 61 67 65 72 6e 65 73 2e 69 6e 69 } //01 00  Sprydstagernes.ini
		$a_01_4 = {70 6e 68 65 64 73 2e 45 75 72 } //00 00  pnheds.Eur
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RPY_MTB_3{
	meta:
		description = "Trojan:Win32/NSISInject.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 00 6e 00 64 00 65 00 72 00 76 00 69 00 73 00 6e 00 69 00 6e 00 67 00 73 00 73 00 79 00 73 00 74 00 65 00 6d 00 65 00 72 00 } //01 00  Undervisningssystemer
		$a_01_1 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 52 00 65 00 6e 00 65 00 77 00 61 00 6c 00 73 00 31 00 32 00 38 00 5c 00 74 00 65 00 6d 00 6e 00 6f 00 73 00 70 00 6f 00 6e 00 64 00 79 00 6c 00 6f 00 75 00 73 00 5c 00 4c 00 64 00 72 00 65 00 70 00 6c 00 65 00 6a 00 65 00 6e 00 73 00 } //01 00  Software\Renewals128\temnospondylous\Ldreplejens
		$a_01_2 = {53 00 75 00 6d 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 65 00 6e 00 73 00 2e 00 53 00 74 00 76 00 } //01 00  Summationens.Stv
		$a_01_3 = {44 00 65 00 6b 00 75 00 70 00 65 00 72 00 65 00 73 00 2e 00 4d 00 79 00 72 00 } //01 00  Dekuperes.Myr
		$a_01_4 = {72 00 65 00 69 00 6d 00 65 00 72 00 74 00 2e 00 57 00 69 00 6c 00 } //00 00  reimert.Wil
	condition:
		any of ($a_*)
 
}