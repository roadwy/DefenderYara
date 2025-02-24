
rule Trojan_Win64_Ulise_AMCP_MTB{
	meta:
		description = "Trojan:Win64/Ulise.AMCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 07 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 31 37 36 2e 31 31 31 2e 31 37 34 2e 31 34 30 2f 62 69 6e 2f 62 6f 74 36 34 2e 62 69 6e } //http://176.111.174.140/bin/bot64.bin  10
		$a_80_1 = {50 72 6f 63 65 73 73 48 61 63 6b 65 72 2e 65 78 65 } //ProcessHacker.exe  3
		$a_80_2 = {70 72 6f 63 65 78 70 36 34 2e 65 78 65 } //procexp64.exe  3
		$a_80_3 = {78 36 34 64 62 67 2e 65 78 65 } //x64dbg.exe  3
		$a_80_4 = {61 75 74 6f 72 75 6e 73 2e 65 78 65 } //autoruns.exe  3
		$a_80_5 = {4e 65 74 66 6c 69 78 20 43 68 65 63 6b 65 72 2e 65 78 65 } //Netflix Checker.exe  1
		$a_80_6 = {41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 73 79 73 61 70 70 65 63 2e 65 78 65 } //Application Data\sysappec.exe  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=18
 
}