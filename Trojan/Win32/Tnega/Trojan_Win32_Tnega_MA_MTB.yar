
rule Trojan_Win32_Tnega_MA_MTB{
	meta:
		description = "Trojan:Win32/Tnega.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {55 00 4e 00 30 00 6c 00 4c 00 33 00 32 00 } //1 UN0lL32
		$a_01_1 = {44 24 20 53 68 65 6c 51 50 } //1 D$ ShelQP
		$a_01_2 = {44 24 2c 6c 45 78 65 } //1 D$,lExe
		$a_01_3 = {44 24 30 63 75 74 65 } //1 D$0cute
		$a_01_4 = {55 6e 68 61 6e 64 6c 65 64 45 78 63 65 70 74 69 6f 6e 46 69 6c 74 65 72 } //1 UnhandledExceptionFilter
		$a_01_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_6 = {44 24 34 45 78 57 } //1 D$4ExW
		$a_01_7 = {44 24 20 43 6c 6f 73 } //1 D$ Clos
		$a_01_8 = {44 24 24 65 48 61 6e } //1 D$$eHan
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}