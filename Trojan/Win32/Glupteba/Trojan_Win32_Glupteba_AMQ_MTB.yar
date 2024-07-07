
rule Trojan_Win32_Glupteba_AMQ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.AMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {72 75 67 6f 78 61 7a 65 77 6f 6a 65 68 61 72 61 72 65 62 61 63 } //rugoxazewojehararebac  3
		$a_80_1 = {6b 69 7a 61 6e 75 67 75 6b 6f 66 75 68 69 64 65 70 75 70 61 74 69 } //kizanugukofuhidepupati  3
		$a_80_2 = {68 69 6c 75 6e 75 6a 75 73 61 66 65 } //hilunujusafe  3
		$a_80_3 = {6a 69 78 61 7a 61 76 6f 62 75 74 6f 7a 69 78 75 68 6f 70 61 } //jixazavobutozixuhopa  3
		$a_80_4 = {5a 6f 6d 62 69 66 79 41 63 74 43 74 78 } //ZombifyActCtx  3
		$a_80_5 = {47 65 74 50 72 6f 63 65 73 73 53 68 75 74 64 6f 77 6e 50 61 72 61 6d 65 74 65 72 73 } //GetProcessShutdownParameters  3
		$a_80_6 = {53 65 74 46 69 72 6d 77 61 72 65 45 6e 76 69 72 6f 6e 6d 65 6e 74 56 61 72 69 61 62 6c 65 41 } //SetFirmwareEnvironmentVariableA  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}