
rule VirTool_WinNT_Rootkitdrv_LR{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.LR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 50 00 72 00 6f 00 52 00 65 00 67 00 } //1 \DosDevices\ProReg
		$a_00_1 = {3f 3f 3f 3b 53 79 73 74 65 6d 3b 53 4d 53 53 2e 45 58 45 3b 43 53 52 53 53 2e 45 58 45 3b 4c 53 41 53 53 2e 45 58 45 3b 57 49 4e 4c 4f 47 4f 4e 2e 45 58 45 3b 53 45 52 56 49 43 45 53 2e 45 58 45 3b 73 76 63 68 6f 73 74 2e 65 78 65 3b } //1 ???;System;SMSS.EXE;CSRSS.EXE;LSASS.EXE;WINLOGON.EXE;SERVICES.EXE;svchost.exe;
		$a_03_2 = {8a 08 40 84 c9 75 f9 2b c2 b9 ff 03 00 00 2b c8 51 8d 85 90 01 02 ff ff 50 8d 85 90 01 02 ff ff 50 e8 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}