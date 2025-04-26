
rule TrojanProxy_Win32_Agent_BS{
	meta:
		description = "TrojanProxy:Win32/Agent.BS,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_01_0 = {76 65 72 73 69 6f 6e 3d 25 64 26 63 61 6e 73 65 6e 64 3d 25 64 26 75 70 64 61 74 65 64 3d 25 64 26 75 75 69 64 3d 25 73 } //4 version=%d&cansend=%d&updated=%d&uuid=%s
		$a_01_1 = {25 73 2f 62 73 65 72 76 2f 62 73 65 72 76 2e 70 68 70 3f 25 73 } //3 %s/bserv/bserv.php?%s
		$a_01_2 = {63 3a 2f 2f 32 2e 74 78 74 } //2 c://2.txt
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2) >=9
 
}