
rule HackTool_Win64_Mikatz_dha_{
	meta:
		description = "HackTool:Win64/Mikatz!dha!!Mikatz.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 0d 00 00 "
		
	strings :
		$a_00_0 = {6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 } //1 mimikatz
		$a_00_1 = {6c 6d 70 61 73 73 77 6f 72 64 } //1 lmpassword
		$a_00_2 = {70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 } //1 password
		$a_00_3 = {75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 00 00 } //1
		$a_00_4 = {73 61 6d 65 6e 75 6d 65 72 61 74 65 64 6f 6d 61 69 6e 73 69 6e 73 61 6d 73 65 72 76 65 72 } //1 samenumeratedomainsinsamserver
		$a_80_5 = {77 69 6e 64 6f 77 73 5c 6b 65 76 6c 61 72 2d 61 70 69 5c 6b 65 76 6c 61 72 73 69 67 73 } //windows\kevlar-api\kevlarsigs  -20
		$a_80_6 = {5c 6b 65 76 6c 61 72 2d 61 70 69 5c 6b 65 76 6c 61 72 73 69 67 73 36 34 5c 78 36 34 5c 72 65 6c 65 61 73 65 5c 48 49 50 48 61 6e 64 6c 65 72 73 36 34 2e 70 64 62 } //\kevlar-api\kevlarsigs64\x64\release\HIPHandlers64.pdb  -20
		$a_80_7 = {5c 6d 63 61 66 65 65 5c 68 6f 73 74 20 69 6e 74 72 75 73 69 6f 6e 20 70 72 65 76 65 6e 74 69 6f 6e 5c 68 69 70 } //\mcafee\host intrusion prevention\hip  -20
		$a_80_8 = {5c 73 64 6b 2e 70 72 6f 74 65 63 74 6f 72 5c 6d 69 6e 6f 72 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 50 72 6f 74 65 63 74 6f 72 36 34 2e 70 64 62 } //\sdk.protector\minor\x64\Release\Protector64.pdb  -20
		$a_80_9 = {6d 6f 72 70 68 69 73 65 63 5f 64 6c 6c 5f 76 65 72 73 69 6f 6e 5f 73 } //morphisec_dll_version_s  -20
		$a_80_10 = {6d 6f 72 70 68 69 73 65 63 5f 70 72 6f 64 75 63 74 5f 76 65 72 73 69 6f 6e 5f 73 } //morphisec_product_version_s  -20
		$a_80_11 = {5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 50 72 6f 74 65 63 74 6f 72 53 65 72 76 69 63 65 36 34 2e 70 64 62 } //\x64\Release\ProtectorService64.pdb  -20
		$a_80_12 = {5c 57 65 72 44 65 62 75 67 67 65 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 78 36 34 5c 77 65 72 64 62 67 2e 70 64 62 } //\WerDebugger\obj\Release\x64\werdbg.pdb  -20
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_80_5  & 1)*-20+(#a_80_6  & 1)*-20+(#a_80_7  & 1)*-20+(#a_80_8  & 1)*-20+(#a_80_9  & 1)*-20+(#a_80_10  & 1)*-20+(#a_80_11  & 1)*-20+(#a_80_12  & 1)*-20) >=5
 
}
rule HackTool_Win64_Mikatz_dha__2{
	meta:
		description = "HackTool:Win64/Mikatz!dha!!Mikatz.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 0b 00 00 "
		
	strings :
		$a_00_0 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 6d 00 69 00 6d 00 69 00 64 00 72 00 76 00 } //1 \DosDevices\mimidrv
		$a_00_1 = {5c 6d 69 6d 69 64 72 76 2e 70 64 62 } //1 \mimidrv.pdb
		$a_00_2 = {6d 00 69 00 6d 00 69 00 64 00 72 00 76 00 20 00 66 00 6f 00 72 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 28 00 6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 } //1 mimidrv for Windows (mimikatz
		$a_00_3 = {52 00 61 00 77 00 20 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 28 00 6e 00 6f 00 74 00 20 00 69 00 6d 00 70 00 6c 00 65 00 6d 00 65 00 6e 00 74 00 65 00 64 00 20 00 79 00 65 00 74 00 29 00 20 00 3a 00 20 00 25 00 73 00 } //1 Raw command (not implemented yet) : %s
		$a_80_4 = {77 69 6e 64 6f 77 73 5c 6b 65 76 6c 61 72 2d 61 70 69 5c 6b 65 76 6c 61 72 73 69 67 73 } //windows\kevlar-api\kevlarsigs  -20
		$a_80_5 = {5c 6b 65 76 6c 61 72 2d 61 70 69 5c 6b 65 76 6c 61 72 73 69 67 73 36 34 5c 78 36 34 5c 72 65 6c 65 61 73 65 5c 48 49 50 48 61 6e 64 6c 65 72 73 36 34 2e 70 64 62 } //\kevlar-api\kevlarsigs64\x64\release\HIPHandlers64.pdb  -20
		$a_80_6 = {5c 6d 63 61 66 65 65 5c 68 6f 73 74 20 69 6e 74 72 75 73 69 6f 6e 20 70 72 65 76 65 6e 74 69 6f 6e 5c 68 69 70 } //\mcafee\host intrusion prevention\hip  -20
		$a_80_7 = {5c 73 64 6b 2e 70 72 6f 74 65 63 74 6f 72 5c 6d 69 6e 6f 72 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 50 72 6f 74 65 63 74 6f 72 36 34 2e 70 64 62 } //\sdk.protector\minor\x64\Release\Protector64.pdb  -20
		$a_80_8 = {6d 6f 72 70 68 69 73 65 63 5f 64 6c 6c 5f 76 65 72 73 69 6f 6e 5f 73 } //morphisec_dll_version_s  -20
		$a_80_9 = {6d 6f 72 70 68 69 73 65 63 5f 70 72 6f 64 75 63 74 5f 76 65 72 73 69 6f 6e 5f 73 } //morphisec_product_version_s  -20
		$a_80_10 = {5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 50 72 6f 74 65 63 74 6f 72 53 65 72 76 69 63 65 36 34 2e 70 64 62 } //\x64\Release\ProtectorService64.pdb  -20
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_80_4  & 1)*-20+(#a_80_5  & 1)*-20+(#a_80_6  & 1)*-20+(#a_80_7  & 1)*-20+(#a_80_8  & 1)*-20+(#a_80_9  & 1)*-20+(#a_80_10  & 1)*-20) >=3
 
}
rule HackTool_Win64_Mikatz_dha__3{
	meta:
		description = "HackTool:Win64/Mikatz!dha!!Mikatz.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 0d 00 00 "
		
	strings :
		$a_00_0 = {70 6f 77 65 72 73 68 65 6c 6c 5f 72 65 66 6c 65 63 74 69 76 65 5f 6d 69 6d 69 6b 61 74 7a } //1 powershell_reflective_mimikatz
		$a_00_1 = {70 6f 77 65 72 6b 61 74 7a 2e 64 6c 6c } //1 powerkatz.dll
		$a_00_2 = {4b 00 49 00 57 00 49 00 5f 00 4d 00 53 00 56 00 31 00 5f 00 30 00 5f 00 43 00 52 00 45 00 44 00 45 00 4e 00 54 00 49 00 41 00 4c 00 53 00 } //1 KIWI_MSV1_0_CREDENTIALS
		$a_00_3 = {67 00 65 00 6e 00 74 00 69 00 6c 00 6b 00 69 00 77 00 69 00 } //1 gentilkiwi
		$a_00_4 = {6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 28 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 29 00 20 00 23 00 20 00 25 00 73 00 } //1 mimikatz(powershell) # %s
		$a_00_5 = {4c 00 53 00 41 00 53 00 53 00 20 00 6d 00 65 00 6d 00 6f 00 72 00 79 00 } //1 LSASS memory
		$a_80_6 = {77 69 6e 64 6f 77 73 5c 6b 65 76 6c 61 72 2d 61 70 69 5c 6b 65 76 6c 61 72 73 69 67 73 } //windows\kevlar-api\kevlarsigs  -20
		$a_80_7 = {5c 6b 65 76 6c 61 72 2d 61 70 69 5c 6b 65 76 6c 61 72 73 69 67 73 36 34 5c 78 36 34 5c 72 65 6c 65 61 73 65 5c 48 49 50 48 61 6e 64 6c 65 72 73 36 34 2e 70 64 62 } //\kevlar-api\kevlarsigs64\x64\release\HIPHandlers64.pdb  -20
		$a_80_8 = {5c 6d 63 61 66 65 65 5c 68 6f 73 74 20 69 6e 74 72 75 73 69 6f 6e 20 70 72 65 76 65 6e 74 69 6f 6e 5c 68 69 70 } //\mcafee\host intrusion prevention\hip  -20
		$a_80_9 = {5c 73 64 6b 2e 70 72 6f 74 65 63 74 6f 72 5c 6d 69 6e 6f 72 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 50 72 6f 74 65 63 74 6f 72 36 34 2e 70 64 62 } //\sdk.protector\minor\x64\Release\Protector64.pdb  -20
		$a_80_10 = {6d 6f 72 70 68 69 73 65 63 5f 64 6c 6c 5f 76 65 72 73 69 6f 6e 5f 73 } //morphisec_dll_version_s  -20
		$a_80_11 = {6d 6f 72 70 68 69 73 65 63 5f 70 72 6f 64 75 63 74 5f 76 65 72 73 69 6f 6e 5f 73 } //morphisec_product_version_s  -20
		$a_80_12 = {5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 50 72 6f 74 65 63 74 6f 72 53 65 72 76 69 63 65 36 34 2e 70 64 62 } //\x64\Release\ProtectorService64.pdb  -20
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_80_6  & 1)*-20+(#a_80_7  & 1)*-20+(#a_80_8  & 1)*-20+(#a_80_9  & 1)*-20+(#a_80_10  & 1)*-20+(#a_80_11  & 1)*-20+(#a_80_12  & 1)*-20) >=3
 
}
rule HackTool_Win64_Mikatz_dha__4{
	meta:
		description = "HackTool:Win64/Mikatz!dha!!Mikatz.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 0d 00 00 "
		
	strings :
		$a_00_0 = {45 00 52 00 52 00 4f 00 52 00 20 00 6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 5f 00 64 00 6f 00 4c 00 6f 00 63 00 61 00 6c 00 20 00 3b 00 20 00 22 00 25 00 73 00 22 00 20 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 6f 00 66 00 20 00 22 00 25 00 73 00 22 00 20 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 20 00 6e 00 6f 00 74 00 20 00 66 00 6f 00 75 00 6e 00 } //1 ERROR mimikatz_doLocal ; "%s" command of "%s" module not foun
		$a_00_1 = {6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 28 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 6c 00 69 00 6e 00 65 00 29 00 20 00 23 00 20 00 25 00 73 00 } //1 mimikatz(commandline) # %s
		$a_00_2 = {67 00 65 00 6e 00 74 00 69 00 6c 00 6b 00 69 00 77 00 69 00 } //1 gentilkiwi
		$a_00_3 = {55 73 65 72 6e 61 6d 65 20 3a 20 25 77 5a } //1 Username : %wZ
		$a_00_4 = {53 65 61 72 63 68 20 66 6f 72 20 4c 53 41 53 53 20 70 72 6f 63 65 73 73 } //1 Search for LSASS process
		$a_00_5 = {6d 69 6d 69 6b 61 74 7a 20 32 2e 30 20 61 6c 70 68 61 20 28 78 36 34 29 } //1 mimikatz 2.0 alpha (x64)
		$a_80_6 = {77 69 6e 64 6f 77 73 5c 6b 65 76 6c 61 72 2d 61 70 69 5c 6b 65 76 6c 61 72 73 69 67 73 } //windows\kevlar-api\kevlarsigs  -20
		$a_80_7 = {5c 6b 65 76 6c 61 72 2d 61 70 69 5c 6b 65 76 6c 61 72 73 69 67 73 36 34 5c 78 36 34 5c 72 65 6c 65 61 73 65 5c 48 49 50 48 61 6e 64 6c 65 72 73 36 34 2e 70 64 62 } //\kevlar-api\kevlarsigs64\x64\release\HIPHandlers64.pdb  -20
		$a_80_8 = {5c 6d 63 61 66 65 65 5c 68 6f 73 74 20 69 6e 74 72 75 73 69 6f 6e 20 70 72 65 76 65 6e 74 69 6f 6e 5c 68 69 70 } //\mcafee\host intrusion prevention\hip  -20
		$a_80_9 = {5c 73 64 6b 2e 70 72 6f 74 65 63 74 6f 72 5c 6d 69 6e 6f 72 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 50 72 6f 74 65 63 74 6f 72 36 34 2e 70 64 62 } //\sdk.protector\minor\x64\Release\Protector64.pdb  -20
		$a_80_10 = {6d 6f 72 70 68 69 73 65 63 5f 64 6c 6c 5f 76 65 72 73 69 6f 6e 5f 73 } //morphisec_dll_version_s  -20
		$a_80_11 = {6d 6f 72 70 68 69 73 65 63 5f 70 72 6f 64 75 63 74 5f 76 65 72 73 69 6f 6e 5f 73 } //morphisec_product_version_s  -20
		$a_80_12 = {5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 50 72 6f 74 65 63 74 6f 72 53 65 72 76 69 63 65 36 34 2e 70 64 62 } //\x64\Release\ProtectorService64.pdb  -20
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_80_6  & 1)*-20+(#a_80_7  & 1)*-20+(#a_80_8  & 1)*-20+(#a_80_9  & 1)*-20+(#a_80_10  & 1)*-20+(#a_80_11  & 1)*-20+(#a_80_12  & 1)*-20) >=3
 
}