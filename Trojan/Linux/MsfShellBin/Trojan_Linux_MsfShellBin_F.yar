
rule Trojan_Linux_MsfShellBin_F{
	meta:
		description = "Trojan:Linux/MsfShellBin.F,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {31 c9 31 db 53 53 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 66 68 ?? ?? 66 68 0a 00 89 e1 6a 1c 51 56 31 db 31 c0 b0 66 b3 03 89 e1 cd 80 31 db 39 d8 75 36 31 c9 f7 e1 89 f3 b0 3f cd 80 31 c0 41 89 f3 b0 3f cd 80 31 c0 41 89 f3 b0 3f cd 80 } //2
		$a_03_1 = {31 db 53 6a 0a f7 e3 89 e3 b0 a2 cd 80 e9 ?? ?? ?? ?? c3 } //1
		$a_01_2 = {31 db f7 e3 6a 06 6a 01 6a 0a 89 e1 b0 66 b3 01 cd 80 89 c6 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}