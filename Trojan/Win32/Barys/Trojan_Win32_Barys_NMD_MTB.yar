
rule Trojan_Win32_Barys_NMD_MTB{
	meta:
		description = "Trojan:Win32/Barys.NMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0a 00 00 "
		
	strings :
		$a_01_0 = {25 73 5c 57 61 72 2e 74 78 74 } //1 %s\War.txt
		$a_01_1 = {57 61 72 20 62 79 20 5b 57 61 72 47 61 6d 65 2c 23 65 6f 66 5d 20 28 20 2a 2a 2a 2a 20 74 69 20 61 6d 6f 20 61 6e 63 68 65 20 73 65 20 74 75 20 6e 6f 6e 20 6d 69 20 72 69 63 61 6d 62 69 } //1 War by [WarGame,#eof] ( **** ti amo anche se tu non mi ricambi
		$a_01_2 = {4e 6f 77 20 69 74 27 73 20 66 75 6e } //1 Now it's fun
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_01_4 = {64 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 6b 69 6c 6c 20 6d 65 } //1 do you want to kill me
		$a_01_5 = {45 6e 63 72 79 70 74 46 69 6c 65 41 } //1 EncryptFileA
		$a_01_6 = {52 65 67 4f 70 65 6e 4b 65 79 45 78 41 } //1 RegOpenKeyExA
		$a_01_7 = {52 65 67 53 65 74 56 61 6c 75 65 45 78 41 } //1 RegSetValueExA
		$a_01_8 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //1 CreateMutexA
		$a_01_9 = {73 6f 6d 65 73 6f 6d 65 57 61 72 5f 45 4f 46 } //2 somesomeWar_EOF
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*2) >=11
 
}