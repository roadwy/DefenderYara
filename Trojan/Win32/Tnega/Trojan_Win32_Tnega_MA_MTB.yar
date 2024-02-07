
rule Trojan_Win32_Tnega_MA_MTB{
	meta:
		description = "Trojan:Win32/Tnega.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 00 4e 00 30 00 6c 00 4c 00 33 00 32 00 } //01 00  UN0lL32
		$a_01_1 = {44 24 20 53 68 65 6c 51 50 } //01 00  D$ ShelQP
		$a_01_2 = {44 24 2c 6c 45 78 65 } //01 00  D$,lExe
		$a_01_3 = {44 24 30 63 75 74 65 } //01 00  D$0cute
		$a_01_4 = {55 6e 68 61 6e 64 6c 65 64 45 78 63 65 70 74 69 6f 6e 46 69 6c 74 65 72 } //01 00  UnhandledExceptionFilter
		$a_01_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_01_6 = {44 24 34 45 78 57 } //01 00  D$4ExW
		$a_01_7 = {44 24 20 43 6c 6f 73 } //01 00  D$ Clos
		$a_01_8 = {44 24 24 65 48 61 6e } //00 00  D$$eHan
	condition:
		any of ($a_*)
 
}