
rule Trojan_BAT_Snukbun_A_dha{
	meta:
		description = "Trojan:BAT/Snukbun.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 "
		
	strings :
		$a_01_0 = {62 63 35 39 37 34 31 33 2d 63 36 61 39 2d 34 66 38 33 2d 62 65 63 33 2d 33 66 34 64 61 39 35 61 63 33 30 38 } //2 bc597413-c6a9-4f83-bec3-3f4da95ac308
		$a_01_1 = {64 64 34 31 63 32 30 62 2d 37 39 33 37 2d 34 36 32 65 2d 61 35 34 37 2d 39 35 63 64 30 65 30 36 37 63 63 34 } //2 dd41c20b-7937-462e-a547-95cd0e067cc4
		$a_01_2 = {74 00 6f 00 6f 00 6c 00 2e 00 65 00 78 00 65 00 20 00 5b 00 5b 00 2d 00 73 00 74 00 61 00 72 00 74 00 5d 00 20 00 7c 00 20 00 5b 00 2d 00 73 00 74 00 6f 00 70 00 5d 00 5d 00 20 00 5b 00 2d 00 73 00 74 00 61 00 74 00 75 00 73 00 5d 00 20 00 5b 00 2d 00 6c 00 6f 00 67 00 5d 00 } //2 tool.exe [[-start] | [-stop]] [-status] [-log]
		$a_01_3 = {4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 20 00 61 00 6c 00 72 00 65 00 61 00 64 00 79 00 20 00 73 00 74 00 61 00 72 00 74 00 65 00 64 00 } //1 Keylogger already started
		$a_01_4 = {44 00 61 00 74 00 61 00 20 00 63 00 6c 00 65 00 61 00 72 00 65 00 64 00 20 00 73 00 75 00 63 00 63 00 65 00 73 00 73 00 66 00 75 00 6c 00 79 00 } //1 Data cleared successfuly
		$a_01_5 = {52 61 62 62 69 74 2e 4c 69 62 } //1 Rabbit.Lib
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=2
 
}