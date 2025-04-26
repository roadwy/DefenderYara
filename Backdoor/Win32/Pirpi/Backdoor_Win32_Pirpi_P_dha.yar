
rule Backdoor_Win32_Pirpi_P_dha{
	meta:
		description = "Backdoor:Win32/Pirpi.P!dha,SIGNATURE_TYPE_PEHSTR_EXT,ffffffe8 03 ffffffe8 03 08 00 00 "
		
	strings :
		$a_00_0 = {4f 70 65 6e 69 6e 67 20 53 65 72 76 69 63 65 20 2e 2e 2e 2e 2e 20 } //1 Opening Service ..... 
		$a_00_1 = {50 4a 5f 6a 58 38 52 5a 4d 42 39 68 6d 7a 4b 45 6e 43 67 34 69 64 6c 46 41 30 35 4c 44 75 32 66 74 6b 59 47 61 33 54 70 57 49 72 63 36 76 51 2e 4e 6f 56 78 4f 31 62 79 37 } //3 PJ_jX8RZMB9hmzKEnCg4idlFA05LDu2ftkYGa3TpWIrc6vQ.NoVxO1by7
		$a_01_2 = {2d 69 6e 73 74 61 6c 6c } //1 -install
		$a_01_3 = {2d 73 68 6f 77 } //1 -show
		$a_01_4 = {2d 72 65 6d 6f 76 65 } //1 -remove
		$a_00_5 = {48 54 54 50 2f 31 2e 31 20 34 30 34 20 4e 6f 74 20 46 6f 75 6e 64 } //1 HTTP/1.1 404 Not Found
		$a_00_6 = {53 65 72 76 65 72 3a 20 4d 69 63 72 6f 73 6f 66 74 2d 49 49 53 2f 36 2e 30 } //1 Server: Microsoft-IIS/6.0
		$a_00_7 = {45 2a 20 43 72 65 61 74 65 46 69 6c 65 28 25 73 29 20 45 72 72 6f 72 28 25 64 29 } //1 E* CreateFile(%s) Error(%d)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=1000
 
}