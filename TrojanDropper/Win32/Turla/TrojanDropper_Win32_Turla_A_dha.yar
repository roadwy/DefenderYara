
rule TrojanDropper_Win32_Turla_A_dha{
	meta:
		description = "TrojanDropper:Win32/Turla.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {b8 af be ad de 39 44 24 08 75 11 39 44 24 0c 75 0b 8b 44 24 04 } //1
		$a_01_1 = {8b 56 3c 8d 04 32 6a 00 bb 0b 01 00 00 66 39 58 18 8b 40 28 6a 01 03 c6 56 ff d0 } //1
		$a_01_2 = {5c 53 79 73 74 65 6d 52 6f 6f 74 5c 25 73 5c 25 73 2e 73 79 73 } //1 \SystemRoot\%s\%s.sys
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}