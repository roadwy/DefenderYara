
rule HackTool_Win64_KduDrv_DA_MTB{
	meta:
		description = "HackTool:Win64/KduDrv.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_81_0 = {6b 65 72 6e 65 6c 6d 6f 64 75 6c 65 75 6e 6c 6f 61 64 65 72 2e 65 78 65 } //1 kernelmoduleunloader.exe
		$a_81_1 = {5c 4b 64 75 50 6f 72 74 } //1 \KduPort
		$a_81_2 = {2d 64 72 76 6e } //1 -drvn
		$a_81_3 = {2d 64 72 76 72 } //1 -drvr
		$a_81_4 = {5c 42 61 73 65 4e 61 6d 65 64 4f 62 6a 65 63 74 73 5c 25 77 73 } //1 \BaseNamedObjects\%ws
		$a_81_5 = {47 6d 65 72 20 27 41 6e 74 69 72 6f 6f 74 6b 69 74 27 } //1 Gmer 'Antirootkit'
		$a_81_6 = {67 6d 65 72 64 72 76 } //1 gmerdrv
		$a_81_7 = {5c 52 45 47 49 53 54 52 59 5c 4d 41 43 48 49 4e 45 5c 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 25 77 73 } //1 \REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\%ws
		$a_81_8 = {5c 4b 6e 6f 77 6e 44 6c 6c 73 5c 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c } //1 \KnownDlls\kernel32.dll
		$a_81_9 = {4d 69 6d 69 6b 61 74 7a 20 6d 69 6d 69 64 72 76 } //1 Mimikatz mimidrv
		$a_81_10 = {53 68 65 6c 6c 63 6f 64 65 20 73 75 70 70 6f 72 74 20 6d 61 73 6b 3a 20 30 78 25 30 38 78 } //1 Shellcode support mask: 0x%08x
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=11
 
}