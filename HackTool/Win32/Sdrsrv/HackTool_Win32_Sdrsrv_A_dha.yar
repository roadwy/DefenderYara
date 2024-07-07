
rule HackTool_Win32_Sdrsrv_A_dha{
	meta:
		description = "HackTool:Win32/Sdrsrv.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,46 00 46 00 0b 00 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 6c 00 2e 00 74 00 6d 00 70 00 } //10 C:\Windows\temp\l.tmp
		$a_01_1 = {61 72 67 73 5b 31 30 5d 20 69 73 20 25 53 20 61 6e 64 20 63 6f 6d 6d 61 6e 64 20 69 73 20 25 53 } //10 args[10] is %S and command is %S
		$a_01_2 = {43 48 45 43 4b 49 4e 47 20 25 64 20 6f 66 20 25 64 } //10 CHECKING %d of %d
		$a_01_3 = {5b 43 4f 55 4e 54 5d 20 25 64 } //10 [COUNT] %d
		$a_01_4 = {5b 46 49 4e 49 53 48 45 44 5d } //10 [FINISHED]
		$a_01_5 = {76 00 6d 00 69 00 6e 00 73 00 74 00 2e 00 74 00 6d 00 70 00 } //10 vminst.tmp
		$a_01_6 = {5b 4f 4b 5d } //10 [OK]
		$a_01_7 = {4c 4f 47 4f 4e 20 55 53 45 52 20 46 41 49 4c 44 20 } //10 LOGON USER FAILD 
		$a_01_8 = {49 4d 50 45 53 4f 4e 41 54 45 20 46 41 49 4c 44 20 } //10 IMPESONATE FAILD 
		$a_01_9 = {45 52 52 4f 52 20 69 6e 20 25 53 2f 25 64 } //10 ERROR in %S/%d
		$a_01_10 = {50 3a 5c 50 72 6f 6a 65 63 74 73 5c 43 2b 2b 5c 54 72 6f 6a 61 6e 5c 54 61 72 67 65 74 5c 53 64 72 73 72 76 5c 57 69 6e 33 32 5c 52 65 6c 65 61 73 65 5c 53 64 72 73 72 76 2e 70 64 62 } //100 P:\Projects\C++\Trojan\Target\Sdrsrv\Win32\Release\Sdrsrv.pdb
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10+(#a_01_8  & 1)*10+(#a_01_9  & 1)*10+(#a_01_10  & 1)*100) >=70
 
}