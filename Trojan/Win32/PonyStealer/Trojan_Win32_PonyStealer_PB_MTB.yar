
rule Trojan_Win32_PonyStealer_PB_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.PB!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4d 00 47 00 5f 00 5f 00 4b 00 56 00 49 00 53 00 2e 00 65 00 78 00 65 00 } //1 MG__KVIS.exe
		$a_01_1 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 ReadProcessMemory
		$a_01_2 = {53 63 68 75 65 72 67 65 72 } //1 Schuerger
		$a_01_3 = {44 61 63 72 79 65 6c 63 6f 73 69 73 } //1 Dacryelcosis
		$a_01_4 = {42 61 6c 73 61 6d 69 63 } //1 Balsamic
		$a_01_5 = {56 69 73 69 74 61 74 69 6f 6e 30 } //1 Visitation0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}