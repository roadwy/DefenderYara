
rule TrojanSpy_Win32_MiniKeyLog_E{
	meta:
		description = "TrojanSpy:Win32/MiniKeyLog.E,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 69 6e 69 20 4b 65 79 20 4c 6f 67 20 2d 20 50 43 20 4d 6f 6e 69 74 6f 72 69 6e 67 20 53 6f 66 74 77 61 72 65 } //3 Mini Key Log - PC Monitoring Software
		$a_01_1 = {20 20 3c 64 65 73 63 72 69 70 74 69 6f 6e 3e 50 43 20 4d 6f 6e 69 74 6f 72 69 6e 67 20 53 6f 66 74 77 61 72 65 3c 2f 64 65 73 63 72 69 70 74 69 6f 6e 3e } //2   <description>PC Monitoring Software</description>
		$a_01_2 = {68 65 63 6b 73 } //1 hecks
		$a_01_3 = {44 49 27 6d 20 73 6f 72 72 79 2c 20 74 68 69 73 20 61 70 70 6c 69 63 61 74 69 6f 6e 20 77 69 6c 6c 20 6e 6f 74 20 72 75 6e 20 77 68 69 6c 65 20 53 6f 66 74 2d 49 63 65 20 69 73 20 72 75 6e 6e 69 6e 67 2e } //1 DI'm sorry, this application will not run while Soft-Ice is running.
		$a_01_4 = {20 32 30 30 32 2d 32 30 30 37 20 62 79 20 62 6c 75 65 2d 73 65 72 69 65 73 } //2  2002-2007 by blue-series
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2) >=4
 
}