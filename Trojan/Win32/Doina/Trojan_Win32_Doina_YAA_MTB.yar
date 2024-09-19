
rule Trojan_Win32_Doina_YAA_MTB{
	meta:
		description = "Trojan:Win32/Doina.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {54 6e 52 44 63 6d 56 68 64 47 56 55 61 48 4a 6c 59 57 52 46 65 41 3d 3d } //1 TnRDcmVhdGVUaHJlYWRFeA==
		$a_01_1 = {54 6e 52 58 63 6d 6c 30 5a 56 5a 70 63 6e 52 31 59 57 78 4e 5a 57 31 76 63 6e 6b 3d } //1 TnRXcml0ZVZpcnR1YWxNZW1vcnk=
		$a_01_2 = {54 6e 52 42 62 47 78 76 59 32 46 30 5a 56 5a 70 63 6e 52 31 59 57 78 4e 5a 57 31 76 63 6e 6b 3d } //1 TnRBbGxvY2F0ZVZpcnR1YWxNZW1vcnk=
		$a_01_3 = {62 6e 52 6b 62 47 77 75 5a 47 78 73 } //1 bnRkbGwuZGxs
		$a_01_4 = {4a 56 4e 35 63 33 52 6c 62 56 4a 76 62 33 51 6c 58 46 78 7a 65 58 4e 30 5a 57 30 7a 4d 6c 78 63 62 6e 52 6b 62 47 77 75 5a 47 78 73 } //1 JVN5c3RlbVJvb3QlXFxzeXN0ZW0zMlxcbnRkbGwuZGxs
		$a_01_5 = {53 65 74 54 6f 73 42 74 4b 62 64 48 6f 6f 6b } //1 SetTosBtKbdHook
		$a_01_6 = {55 6e 48 6f 6f 6b 54 6f 73 42 74 4b 62 64 } //1 UnHookTosBtKbd
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}