
rule Trojan_Win64_Tedy_C_MTB{
	meta:
		description = "Trojan:Win64/Tedy.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 "
		
	strings :
		$a_01_0 = {6f 6c 6c 79 64 62 67 2e 65 78 65 } //2 ollydbg.exe
		$a_01_1 = {78 36 34 64 62 67 2e 65 78 65 } //2 x64dbg.exe
		$a_01_2 = {78 33 32 64 62 67 2e 65 78 65 } //2 x32dbg.exe
		$a_01_3 = {50 72 6f 63 65 73 73 20 48 61 63 6b 65 72 20 32 } //2 Process Hacker 2
		$a_01_4 = {57 69 72 65 73 68 61 72 6b } //2 Wireshark
		$a_01_5 = {40 46 41 43 4b 20 59 4f 55 20 44 6f 6e 6b 65 79 2e } //3 @FACK YOU Donkey.
		$a_01_6 = {6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 66 69 72 65 77 61 6c 6c 20 64 65 6c 65 74 65 20 72 75 6c 65 20 6e 61 6d 65 } //3 netsh advfirewall firewall delete rule name
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*3+(#a_01_6  & 1)*3) >=14
 
}