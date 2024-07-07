
rule Backdoor_Win32_Hackdef_gen_C{
	meta:
		description = "Backdoor:Win32/Hackdef.gen!C,SIGNATURE_TYPE_PEHSTR,18 00 18 00 0d 00 00 "
		
	strings :
		$a_01_0 = {5c 5c 2e 5c 4d 61 69 6c 73 6c 6f 74 5c 63 72 73 73 2d 78 64 31 33 30 73 } //2 \\.\Mailslot\crss-xd130s
		$a_01_1 = {5c 5c 2e 5c 4d 61 69 6c 73 6c 6f 74 5c 63 72 73 73 2d 78 64 63 } //2 \\.\Mailslot\crss-xdc
		$a_01_2 = {5c 5c 2e 5c 4d 61 69 6c 73 6c 6f 74 5c 63 72 73 73 2d 78 64 62 } //2 \\.\Mailslot\crss-xdb
		$a_01_3 = {5c 5c 2e 5c 63 72 73 73 44 72 69 76 65 72 } //2 \\.\crssDriver
		$a_01_4 = {2d 3a 62 64 3a 2d } //3 -:bd:-
		$a_01_5 = {2d 69 6e 73 74 61 6c 6c } //3 -install
		$a_01_6 = {2d 72 65 66 72 65 73 68 } //3 -refresh
		$a_01_7 = {2d 73 74 61 72 74 } //3 -start
		$a_01_8 = {2d 75 6e 69 6e 73 74 61 6c 6c } //3 -uninstall
		$a_01_9 = {2d 62 61 63 6b 64 6f 6f 72 3a 2d } //3 -backdoor:-
		$a_01_10 = {4f 70 65 6e 53 65 72 76 69 63 65 41 } //2 OpenServiceA
		$a_01_11 = {4f 70 65 6e 53 43 4d 61 6e 61 67 65 72 41 } //2 OpenSCManagerA
		$a_01_12 = {4c 6f 63 6b 53 65 72 76 69 63 65 44 61 74 61 62 61 73 65 } //2 LockServiceDatabase
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3+(#a_01_6  & 1)*3+(#a_01_7  & 1)*3+(#a_01_8  & 1)*3+(#a_01_9  & 1)*3+(#a_01_10  & 1)*2+(#a_01_11  & 1)*2+(#a_01_12  & 1)*2) >=24
 
}