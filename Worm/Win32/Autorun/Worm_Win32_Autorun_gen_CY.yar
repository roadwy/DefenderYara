
rule Worm_Win32_Autorun_gen_CY{
	meta:
		description = "Worm:Win32/Autorun.gen!CY,SIGNATURE_TYPE_PEHSTR_EXT,2b 00 2b 00 08 00 00 0a 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //0a 00  MSVBVM60.DLL
		$a_01_1 = {62 79 74 65 73 54 6f 74 61 6c 00 00 46 6e 61 6d 65 00 00 00 6d 73 45 73 70 65 72 61 00 00 00 00 69 6e 74 65 72 76 61 6c 00 00 00 00 46 69 6c 65 4e 61 6d 65 00 00 00 00 64 69 73 63 6f 00 00 00 } //0a 00 
		$a_01_2 = {43 3a 5c 41 72 63 68 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 5c 4d 65 73 73 65 6e 67 65 72 5c 6d 73 6d 73 67 73 2e 65 78 65 } //0a 00  C:\Archivos de programa\Messenger\msmsgs.exe
		$a_00_3 = {44 00 3a 00 5c 00 53 00 6f 00 75 00 72 00 63 00 65 00 73 00 5c 00 56 00 42 00 61 00 73 00 69 00 63 00 5c 00 48 00 75 00 67 00 6f 00 20 00 32 00 2e 00 30 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //01 00  D:\Sources\VBasic\Hugo 2.0\Project1.vbp
		$a_01_4 = {4d 6f 64 53 6f 63 6b 65 74 4d 61 73 74 65 72 } //01 00  ModSocketMaster
		$a_01_5 = {43 6c 69 65 6e 74 5f 44 61 74 61 41 72 72 69 76 61 6c } //01 00  Client_DataArrival
		$a_01_6 = {52 65 6d 6f 74 65 48 6f 73 74 } //01 00  RemoteHost
		$a_01_7 = {73 55 52 4c 46 69 6c 65 4e 61 6d 65 } //00 00  sURLFileName
	condition:
		any of ($a_*)
 
}