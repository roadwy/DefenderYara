
rule HackTool_Win32_Panddos_A{
	meta:
		description = "HackTool:Win32/Panddos.A,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 0b 00 00 0a 00 "
		
	strings :
		$a_00_0 = {25 73 5c 4e 65 74 42 6f 74 2e 69 6e 69 } //0a 00  %s\NetBot.ini
		$a_00_1 = {4e 65 74 42 6f 74 20 41 74 74 61 63 6b 65 72 } //0a 00  NetBot Attacker
		$a_00_2 = {68 61 63 6b 65 72 6f 6f 2e 33 33 32 32 2e 6f 72 67 } //0a 00  hackeroo.3322.org
		$a_00_3 = {77 77 77 2e 68 61 63 6b 65 72 6f 6f 2e 63 6f 6d } //0a 00  www.hackeroo.com
		$a_00_4 = {4e 65 74 42 6f 74 2e 44 44 4f 53 2e 54 65 61 6d } //0a 00  NetBot.DDOS.Team
		$a_00_5 = {50 61 6e 64 61 20 44 44 6f 73 } //0a 00  Panda DDos
		$a_00_6 = {77 77 77 2e 6e 62 64 64 6f 73 2e 63 6f 6d 2f 61 74 74 61 63 6b 2e 74 78 74 } //01 00  www.nbddos.com/attack.txt
		$a_00_7 = {5c 5c 2e 5c 53 49 43 45 } //01 00  \\.\SICE
		$a_00_8 = {5c 5c 2e 5c 53 49 57 56 49 44 } //01 00  \\.\SIWVID
		$a_00_9 = {5c 5c 2e 5c 4e 54 49 43 45 } //0a 00  \\.\NTICE
		$a_02_10 = {6e 65 74 20 6c 6f 63 61 6c 67 72 6f 75 70 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 73 20 90 02 0a 20 2f 61 64 64 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}