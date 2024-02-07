
rule VirTool_WinNT_Rootkitdrv_KC{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.KC,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 10 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 65 53 65 74 45 76 65 6e 74 } //01 00  KeSetEvent
		$a_01_1 = {4f 69 57 78 65 67 6f 45 78 78 65 67 6c 54 76 73 67 69 77 77 } //01 00  OiWxegoExxeglTvsgiww
		$a_01_2 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //01 00  explorer.exe
		$a_01_3 = {4f 69 4d 72 6d 78 6d 65 70 6d 64 69 45 74 67 } //01 00  OiMrmxmepmdiEtg
		$a_01_4 = {5a 77 57 72 69 74 65 46 69 6c 65 } //01 00  ZwWriteFile
		$a_01_5 = {6e 74 6f 73 6b 72 6e 6c 2e 65 78 65 } //01 00  ntoskrnl.exe
		$a_01_6 = {5c 44 6f 73 44 65 76 69 63 65 73 5c } //01 00  \DosDevices\
		$a_01_7 = {69 62 74 70 73 76 69 76 2e 69 62 69 } //01 00  ibtpsviv.ibi
		$a_01_8 = {6d 73 64 6e 33 32 2e 74 6c 66 } //01 00  msdn32.tlf
		$a_01_9 = {71 77 68 72 37 36 2e 78 70 6a } //01 00  qwhr76.xpj
		$a_01_10 = {72 78 6f 76 72 70 74 65 2e 69 62 69 } //01 00  rxovrpte.ibi
		$a_01_11 = {5c 73 79 73 74 65 6d 33 32 } //01 00  \system32
		$a_01_12 = {6e 74 6b 72 6e 6c 70 61 2e 65 78 65 } //01 00  ntkrnlpa.exe
		$a_01_13 = {49 6f 43 72 65 61 74 65 44 65 76 69 63 65 } //01 00  IoCreateDevice
		$a_01_14 = {4f 69 59 72 77 78 65 67 6f 48 69 78 65 67 6c 54 76 73 67 69 77 77 } //01 00  OiYrwxegoHixeglTvsgiww
		$a_01_15 = {51 71 51 65 74 50 73 67 6f 69 68 54 65 6b 69 77 57 74 69 67 6d 6a 63 47 65 67 6c 69 } //00 00  QqQetPsgoihTekiwWtigmjcGegli
	condition:
		any of ($a_*)
 
}