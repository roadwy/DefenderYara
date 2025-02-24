
rule Trojan_BAT_KillProc_MA_MTB{
	meta:
		description = "Trojan:BAT/KillProc.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {4d 00 65 00 6d 00 6f 00 72 00 79 00 44 00 69 00 61 00 67 00 6e 00 6f 00 73 00 74 00 69 00 63 00 2e 00 65 00 78 00 65 00 } //1 MemoryDiagnostic.exe
		$a_00_1 = {24 34 38 33 65 62 33 30 63 2d 31 31 62 64 2d 34 33 33 35 2d 62 36 37 32 2d 33 65 37 61 33 34 61 30 32 62 61 37 } //1 $483eb30c-11bd-4335-b672-3e7a34a02ba7
		$a_80_2 = {4d 69 6e 68 61 4c 69 69 73 74 61 61 73 } //MinhaLiistaas  1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}