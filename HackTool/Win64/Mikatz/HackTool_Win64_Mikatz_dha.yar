
rule HackTool_Win64_Mikatz_dha{
	meta:
		description = "HackTool:Win64/Mikatz!dha,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 } //1 mimikatz
		$a_01_1 = {6c 6d 70 61 73 73 77 6f 72 64 } //1 lmpassword
		$a_01_2 = {70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 } //1 password
		$a_01_3 = {75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 00 00 } //1
		$a_01_4 = {73 61 6d 65 6e 75 6d 65 72 61 74 65 64 6f 6d 61 69 6e 73 69 6e 73 61 6d 73 65 72 76 65 72 } //1 samenumeratedomainsinsamserver
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule HackTool_Win64_Mikatz_dha_2{
	meta:
		description = "HackTool:Win64/Mikatz!dha,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 6d 00 69 00 6d 00 69 00 64 00 72 00 76 00 } //1 \DosDevices\mimidrv
		$a_01_1 = {5c 6d 69 6d 69 64 72 76 2e 70 64 62 } //1 \mimidrv.pdb
		$a_01_2 = {6d 00 69 00 6d 00 69 00 64 00 72 00 76 00 20 00 66 00 6f 00 72 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 28 00 6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 } //1 mimidrv for Windows (mimikatz
		$a_01_3 = {52 00 61 00 77 00 20 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 28 00 6e 00 6f 00 74 00 20 00 69 00 6d 00 70 00 6c 00 65 00 6d 00 65 00 6e 00 74 00 65 00 64 00 20 00 79 00 65 00 74 00 29 00 20 00 3a 00 20 00 25 00 73 00 } //1 Raw command (not implemented yet) : %s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule HackTool_Win64_Mikatz_dha_3{
	meta:
		description = "HackTool:Win64/Mikatz!dha,SIGNATURE_TYPE_PEHSTR,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {45 00 52 00 52 00 4f 00 52 00 20 00 6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 5f 00 64 00 6f 00 4c 00 6f 00 63 00 61 00 6c 00 20 00 3b 00 20 00 22 00 25 00 73 00 22 00 20 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 6f 00 66 00 20 00 22 00 25 00 73 00 22 00 20 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 20 00 6e 00 6f 00 74 00 20 00 66 00 6f 00 75 00 6e 00 } //1 ERROR mimikatz_doLocal ; "%s" command of "%s" module not foun
		$a_01_1 = {6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 28 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 6c 00 69 00 6e 00 65 00 29 00 20 00 23 00 20 00 25 00 73 00 } //1 mimikatz(commandline) # %s
		$a_01_2 = {67 00 65 00 6e 00 74 00 69 00 6c 00 6b 00 69 00 77 00 69 00 } //1 gentilkiwi
		$a_01_3 = {55 73 65 72 6e 61 6d 65 20 3a 20 25 77 5a } //1 Username : %wZ
		$a_01_4 = {53 65 61 72 63 68 20 66 6f 72 20 4c 53 41 53 53 20 70 72 6f 63 65 73 73 } //1 Search for LSASS process
		$a_01_5 = {6d 69 6d 69 6b 61 74 7a 20 32 2e 30 20 61 6c 70 68 61 20 28 78 36 34 29 } //1 mimikatz 2.0 alpha (x64)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}