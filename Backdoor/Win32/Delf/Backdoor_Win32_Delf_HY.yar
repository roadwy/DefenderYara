
rule Backdoor_Win32_Delf_HY{
	meta:
		description = "Backdoor:Win32/Delf.HY,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 52 49 56 4d 53 47 20 5f 54 69 61 67 6f 5f 5f 20 23 78 70 63 20 50 69 6e 67 20 64 61 20 6d 6f 72 74 65 20 61 74 69 76 61 64 6f 21 21 20 3a 44 } //1 PRIVMSG _Tiago__ #xpc Ping da morte ativado!! :D
		$a_01_1 = {50 52 49 56 4d 53 47 20 5f 54 69 61 67 6f 5f 5f 20 23 78 70 63 20 42 75 66 66 65 72 20 61 6c 74 65 72 61 64 6f 20 70 61 72 61 3a } //1 PRIVMSG _Tiago__ #xpc Buffer alterado para:
		$a_01_2 = {74 61 73 6b 6b 69 6c 6c 20 2d 66 20 2d 69 6d 20 70 69 6e 67 2e 65 78 65 } //1 taskkill -f -im ping.exe
		$a_01_3 = {49 52 43 20 43 68 61 6e 6e 65 6c 20 4c 69 6e 6b 65 72 20 28 63 29 20 43 52 45 45 51 } //1 IRC Channel Linker (c) CREEQ
		$a_01_4 = {79 61 68 6f 6f 62 75 64 64 79 6d 61 69 6e } //1 yahoobuddymain
		$a_01_5 = {79 61 68 6f 6f 21 20 6d 65 73 73 65 6e 67 65 72 } //1 yahoo! messenger
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}