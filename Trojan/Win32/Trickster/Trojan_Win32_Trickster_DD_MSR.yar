
rule Trojan_Win32_Trickster_DD_MSR{
	meta:
		description = "Trojan:Win32/Trickster.DD!MSR,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4b 69 6c 6c 54 69 6d 65 72 } //1 KillTimer
		$a_01_1 = {73 68 65 6c 6c 65 78 65 63 75 74 65 61 } //1 shellexecutea
		$a_01_2 = {43 72 79 70 74 53 74 72 69 6e 67 54 6f 42 69 6e 61 72 79 41 } //1 CryptStringToBinaryA
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_4 = {54 72 61 69 6e 65 72 5f 53 74 72 6f 6e 67 68 6f 6c 64 } //1 Trainer_Stronghold
		$a_01_5 = {54 00 72 00 61 00 69 00 6e 00 65 00 72 00 5f 00 44 00 65 00 73 00 70 00 65 00 72 00 61 00 64 00 6f 00 73 00 2e 00 45 00 58 00 45 00 } //1 Trainer_Desperados.EXE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}