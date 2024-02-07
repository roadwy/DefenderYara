
rule Trojan_Win32_Fsysna_CM_MTB{
	meta:
		description = "Trojan:Win32/Fsysna.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 64 61 76 69 64 20 65 67 67 69 6e 73 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 53 74 72 69 6b 65 46 4e 5c 53 74 72 69 6b 65 46 4e 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 53 74 72 69 6b 65 46 4e 2e 70 64 62 } //01 00  C:\Users\david eggins\source\repos\StrikeFN\StrikeFN\obj\Release\StrikeFN.pdb
		$a_80_1 = {53 74 72 69 6b 65 46 4e 2e 65 78 65 } //StrikeFN.exe  01 00 
		$a_01_2 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  CheckRemoteDebuggerPresent
		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_4 = {53 61 66 65 6e 67 69 6e 65 20 53 68 69 65 6c 64 65 6e } //01 00  Safengine Shielden
		$a_01_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_01_6 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //00 00  GetTickCount
	condition:
		any of ($a_*)
 
}