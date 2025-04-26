
rule HackTool_Win32_JuicyPotato_F_dha{
	meta:
		description = "HackTool:Win32/JuicyPotato.F!dha,SIGNATURE_TYPE_PEHSTR,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {5b 2a 5d 20 42 72 75 74 65 66 6f 72 63 69 6e 67 20 25 64 20 43 4c 53 49 44 73 2e 2e 2e } //1 [*] Bruteforcing %d CLSIDs...
		$a_01_1 = {5b 2a 5d 20 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 20 46 69 72 65 77 61 6c 6c 20 6e 6f 74 20 65 6e 61 62 6c 65 64 2e 20 45 76 65 72 79 20 43 4f 4d 20 70 6f 72 74 20 77 69 6c 6c 20 77 6f 72 6b 2e } //1 [*] Windows Defender Firewall not enabled. Every COM port will work.
		$a_01_2 = {5b 2d 5d 20 54 68 65 20 70 72 69 76 69 6c 65 67 65 64 20 70 72 6f 63 65 73 73 20 66 61 69 6c 65 64 20 74 6f 20 63 6f 6d 6d 75 6e 69 63 61 74 65 20 77 69 74 68 20 6f 75 72 20 43 4f 4d 20 53 65 72 76 65 72 20 3a 28 20 54 72 79 20 61 20 64 69 66 66 65 72 65 6e 74 20 43 4f 4d 20 70 6f 72 74 20 69 6e 20 74 68 65 20 2d 6c 20 66 6c 61 67 2e } //1 [-] The privileged process failed to communicate with our COM Server :( Try a different COM port in the -l flag.
		$a_01_3 = {5b 2b 5d 20 61 75 74 68 72 65 73 75 6c 74 20 73 75 63 63 65 73 73 20 25 53 3b 25 53 5c 25 53 3b 25 53 } //1 [+] authresult success %S;%S\%S;%S
		$a_01_4 = {5b 2b 5d 20 45 78 70 6c 6f 69 74 20 73 75 63 63 65 73 73 66 75 6c 21 } //2 [+] Exploit successful!
		$a_01_5 = {4a 00 75 00 69 00 63 00 79 00 50 00 6f 00 74 00 61 00 74 00 6f 00 4e 00 47 00 } //3 JuicyPotatoNG
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2+(#a_01_5  & 1)*3) >=4
 
}