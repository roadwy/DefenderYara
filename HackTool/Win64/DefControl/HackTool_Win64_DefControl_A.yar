
rule HackTool_Win64_DefControl_A{
	meta:
		description = "HackTool:Win64/DefControl.A,SIGNATURE_TYPE_PEHSTR,06 00 06 00 0b 00 00 "
		
	strings :
		$a_01_0 = {67 6f 2d 77 69 6e 69 6f 2e 65 6e 61 62 6c 65 44 69 73 61 62 6c 65 50 72 6f 63 65 73 73 50 72 69 76 69 6c 65 67 65 } //2 go-winio.enableDisableProcessPrivilege
		$a_01_1 = {69 6d 70 65 72 73 6f 6e 61 74 65 20 53 59 53 54 45 4d 3a } //1 impersonate SYSTEM:
		$a_01_2 = {69 6d 70 65 72 73 6f 6e 61 74 65 20 54 52 55 53 54 45 44 49 4e 53 54 41 4c 4c 45 52 3a } //1 impersonate TRUSTEDINSTALLER:
		$a_01_3 = {6d 61 69 6e 2e 54 52 55 53 54 45 44 49 4e 53 54 41 4c 4c 45 52 } //2 main.TRUSTEDINSTALLER
		$a_01_4 = {6d 61 69 6e 2e 69 6d 70 65 72 73 6f 6e 61 74 65 } //2 main.impersonate
		$a_01_5 = {2f 78 2f 73 79 73 2f 77 69 6e 64 6f 77 73 2e 41 43 4c 46 72 6f 6d 45 6e 74 72 69 65 73 } //2 /x/sys/windows.ACLFromEntries
		$a_01_6 = {45 72 72 6f 72 20 65 78 74 72 61 63 74 69 6e 67 20 44 41 43 4c 3a 20 25 76 } //1 Error extracting DACL: %v
		$a_01_7 = {63 61 6e 6e 6f 74 20 63 72 65 61 74 65 20 6e 65 77 20 41 43 4c 3a } //1 cannot create new ACL:
		$a_01_8 = {52 65 6d 6f 76 65 20 61 6c 6c 20 44 45 4e 59 20 41 43 4c 73 20 66 72 6f 6d } //1 Remove all DENY ACLs from
		$a_01_9 = {57 69 6e 44 65 66 65 6e 64 4d 44 43 6f 72 65 53 76 63 } //1 WinDefendMDCoreSvc
		$a_01_10 = {6d 70 73 73 76 63 77 73 63 73 76 63 } //1 mpssvcwscsvc
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=6
 
}