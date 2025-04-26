
rule Trojan_Win64_KillMBR_RPX_MTB{
	meta:
		description = "Trojan:Win64/KillMBR.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 2e 66 } //1 cmd.f
		$a_01_1 = {25 2f 6e 6f 62 72 65 61 6b 20 20 20 2f 43 20 20 74 69 6d 65 6f 75 74 20 31 20 26 20 20 20 20 20 6d 6f 76 65 20 } //1 %/nobreak   /C  timeout 1 &     move 
		$a_01_2 = {55 6e 74 69 74 6c 65 64 2e 63 76 73 } //1 Untitled.cvs
		$a_01_3 = {64 69 72 20 20 26 20 76 65 72 20 26 20 74 72 65 65 20 26 20 20 65 72 61 73 65 20 20 20 2f 66 20 20 20 2f 71 } //1 dir  & ver & tree &  erase   /f   /q
		$a_01_4 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //1 \\.\PhysicalDrive0
		$a_01_5 = {6c 6c 2e 64 66 } //1 ll.df
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}