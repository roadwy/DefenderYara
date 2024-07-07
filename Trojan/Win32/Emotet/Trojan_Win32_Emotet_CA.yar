
rule Trojan_Win32_Emotet_CA{
	meta:
		description = "Trojan:Win32/Emotet.CA,SIGNATURE_TYPE_PEHSTR,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 00 65 00 6d 00 6f 00 53 00 68 00 69 00 65 00 6c 00 64 00 } //2 DemoShield
		$a_01_1 = {67 00 7a 00 33 00 43 00 6d 00 6f 00 73 00 74 00 63 00 6f 00 6d 00 70 00 6c 00 65 00 74 00 65 00 6c 00 79 00 } //2 gz3Cmostcompletely
		$a_01_2 = {50 53 58 50 53 58 50 53 58 50 53 58 50 53 58 50 53 58 66 66 66 66 66 } //4 PSXPSXPSXPSXPSXPSXfffff
		$a_01_3 = {6d 00 61 00 63 00 72 00 6f 00 2e 00 65 00 78 00 65 00 } //2 macro.exe
		$a_01_4 = {77 00 65 00 72 00 65 00 6e 00 69 00 63 00 6f 00 6e 00 61 00 73 00 7a 00 46 00 6c 00 61 00 73 00 68 00 } //2 wereniconaszFlash
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*4+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=6
 
}