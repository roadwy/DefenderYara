
rule Trojan_Win32_Convagent_BD_MTB{
	meta:
		description = "Trojan:Win32/Convagent.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {97 08 18 78 64 81 50 07 e8 eb 46 86 d9 01 92 86 1b 31 ac d0 40 a1 0f 90 d0 97 88 1e e0 80 c1 02 2e ac e1 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Convagent_BD_MTB_2{
	meta:
		description = "Trojan:Win32/Convagent.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 6e 72 65 67 69 73 74 65 72 43 6c 61 73 73 41 } //01 00  UnregisterClassA
		$a_01_1 = {43 00 3a 00 5c 00 42 00 75 00 67 00 72 00 65 00 70 00 6f 00 72 00 74 00 5f 00 65 00 72 00 72 00 6f 00 72 00 2e 00 69 00 6e 00 69 00 } //01 00  C:\Bugreport_error.ini
		$a_01_2 = {6e 6a 6a 6f 63 } //01 00  njjoc
		$a_01_3 = {57 41 71 72 72 73 69 66 } //01 00  WAqrrsif
		$a_01_4 = {44 4c 4c 20 45 52 52 4f 52 } //00 00  DLL ERROR
	condition:
		any of ($a_*)
 
}