
rule Trojan_Win32_SquirrelWaffle_EM_MTB{
	meta:
		description = "Trojan:Win32/SquirrelWaffle.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 06 00 00 "
		
	strings :
		$a_00_0 = {51 8d 4c 24 04 2b c8 1b c0 f7 d0 23 c8 8b c4 25 00 f0 ff ff } //10
		$a_81_1 = {42 72 6f 61 64 63 6f 6d 20 4e 65 74 58 74 72 65 6d 65 20 47 69 67 61 62 69 74 20 45 74 68 65 72 6e 65 74 } //3 Broadcom NetXtreme Gigabit Ethernet
		$a_81_2 = {76 5a 44 49 74 41 5a 48 76 64 57 64 5a 69 4a 66 49 4c 45 41 67 57 48 4d 4f 56 75 6b 78 4a 51 6e 6c 6a 49 4e 49 56 6f 4a 6e 46 64 68 51 54 73 67 4e 50 6d 72 75 79 5a 62 } //3 vZDItAZHvdWdZiJfILEAgWHMOVukxJQnljINIVoJnFdhQTsgNPmruyZb
		$a_81_3 = {41 50 50 44 41 54 41 } //3 APPDATA
		$a_81_4 = {63 5c 68 6a 6d 54 50 } //3 c\hjmTP
		$a_81_5 = {44 6c 6c 31 2e 70 64 62 } //3 Dll1.pdb
	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3) >=25
 
}