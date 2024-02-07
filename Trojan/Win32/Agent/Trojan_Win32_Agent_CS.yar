
rule Trojan_Win32_Agent_CS{
	meta:
		description = "Trojan:Win32/Agent.CS,SIGNATURE_TYPE_PEHSTR,ffffffac 00 ffffffac 00 0d 00 00 64 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //0a 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {40 6d 73 6e 2e 63 6f 6d 2e 62 72 } //0a 00  @msn.com.br
		$a_01_2 = {6d 73 6e 6d 73 67 72 2e 65 78 65 } //0a 00  msnmsgr.exe
		$a_01_3 = {4d 73 6e 48 65 6c 70 65 72 4f 62 6a } //0a 00  MsnHelperObj
		$a_01_4 = {52 65 6d 6f 74 65 4d 61 63 68 69 6e 65 4e 61 6d 65 } //0a 00  RemoteMachineName
		$a_01_5 = {57 53 41 53 74 61 72 74 75 70 } //0a 00  WSAStartup
		$a_01_6 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //0a 00  CreateToolhelp32Snapshot
		$a_01_7 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  Toolhelp32ReadProcessMemory
		$a_01_8 = {61 76 67 63 63 2e 65 78 65 } //01 00  avgcc.exe
		$a_01_9 = {4e 41 56 57 33 32 2e 45 58 45 } //01 00  NAVW32.EXE
		$a_01_10 = {4e 50 46 4d 4e 54 4f 52 2e 45 58 45 } //01 00  NPFMNTOR.EXE
		$a_01_11 = {53 4e 44 53 72 76 63 2e 65 78 65 } //01 00  SNDSrvc.exe
		$a_01_12 = {43 43 41 50 50 2e 45 58 45 } //00 00  CCAPP.EXE
	condition:
		any of ($a_*)
 
}