
rule Trojan_Win64_Barys_VX_MTB{
	meta:
		description = "Trojan:Win64/Barys.VX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {48 44 2d 50 6c 61 79 65 72 2e 65 78 65 } //1 HD-Player.exe
		$a_01_1 = {4d 45 6d 75 48 65 61 64 6c 65 73 73 2e 65 78 65 } //1 MEmuHeadless.exe
		$a_01_2 = {4c 64 56 42 6f 78 48 65 61 64 6c 65 73 73 2e 65 78 65 } //1 LdVBoxHeadless.exe
		$a_01_3 = {49 6e 74 65 72 6e 65 74 20 42 6c 6f 63 6b 3a 20 45 6e 61 62 6c 65 64 } //1 Internet Block: Enabled
		$a_01_4 = {6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 66 69 72 65 77 61 6c 6c 20 64 65 6c 65 74 65 20 72 75 6c 65 20 6e 61 6d 65 3d 61 6c 6c 20 70 72 6f 67 72 61 6d 3d } //1 netsh advfirewall firewall delete rule name=all program=
		$a_01_5 = {6a 6f 65 62 6f 78 63 6f 6e 74 72 6f 6c 2e 65 78 65 } //1 joeboxcontrol.exe
		$a_01_6 = {46 69 64 64 6c 65 72 2e 65 78 65 } //1 Fiddler.exe
		$a_01_7 = {6a 6f 65 62 6f 78 73 65 72 76 65 72 2e 65 78 65 } //1 joeboxserver.exe
		$a_01_8 = {49 6d 6d 75 6e 69 74 79 44 65 62 75 67 67 65 72 2e 65 78 65 } //1 ImmunityDebugger.exe
		$a_01_9 = {57 69 72 65 73 68 61 72 6b 2e 65 78 65 } //1 Wireshark.exe
		$a_01_10 = {6f 6c 6c 79 64 62 67 2e 65 78 65 } //1 ollydbg.exe
		$a_01_11 = {50 72 6f 63 65 73 73 48 61 63 6b 65 72 2e 65 78 65 } //1 ProcessHacker.exe
		$a_01_12 = {44 75 6d 70 2d 46 69 78 65 72 2e 65 78 65 } //1 Dump-Fixer.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}