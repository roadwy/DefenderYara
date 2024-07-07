
rule HackTool_Win32_Onaht_A{
	meta:
		description = "HackTool:Win32/Onaht.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {5b 4f 4e 48 41 54 5d 20 43 4f 4e 4e 45 43 54 53 20 28 25 64 2e 25 64 2e 25 64 2e 25 64 2c 20 25 64 2e 25 64 2e 25 64 2e 25 64 2c 20 25 64 29 } //1 [ONHAT] CONNECTS (%d.%d.%d.%d, %d.%d.%d.%d, %d)
		$a_01_1 = {5b 4f 4e 48 41 54 5d 20 41 43 43 45 50 54 53 20 28 25 64 2e 25 64 2e 25 64 2e 25 64 2c 20 25 64 29 } //1 [ONHAT] ACCEPTS (%d.%d.%d.%d, %d)
		$a_01_2 = {5b 4f 4e 48 41 54 5d 20 4c 49 53 54 45 4e 53 20 28 25 64 2e 25 64 2e 25 64 2e 25 64 2c 20 25 64 29 } //1 [ONHAT] LISTENS (%d.%d.%d.%d, %d)
		$a_01_3 = {4f 4e 54 41 48 2e 45 58 45 20 2d 68 20 46 4f 52 20 48 45 4c 50 20 49 4e 46 4f 52 4d 41 54 49 4f 4e } //2 ONTAH.EXE -h FOR HELP INFORMATION
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=3
 
}