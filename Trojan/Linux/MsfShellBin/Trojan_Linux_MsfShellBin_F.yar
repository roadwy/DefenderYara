
rule Trojan_Linux_MsfShellBin_F{
	meta:
		description = "Trojan:Linux/MsfShellBin.F,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {31 c9 31 db 53 53 68 90 01 04 68 90 01 04 68 90 01 04 68 90 01 04 53 66 68 90 01 02 66 68 0a 00 89 e1 6a 1c 51 56 31 db 31 c0 b0 66 b3 03 89 e1 cd 80 31 db 39 d8 75 36 31 c9 f7 e1 89 f3 b0 3f cd 80 31 c0 41 89 f3 b0 3f cd 80 31 c0 41 89 f3 b0 3f cd 80 90 00 } //01 00 
		$a_03_1 = {31 db 53 6a 0a f7 e3 89 e3 b0 a2 cd 80 e9 90 01 04 c3 90 00 } //01 00 
		$a_01_2 = {31 db f7 e3 6a 06 6a 01 6a 0a 89 e1 b0 66 b3 01 cd 80 89 c6 } //00 00 
	condition:
		any of ($a_*)
 
}