
rule Ransom_Win32_Balaclava_AR_MTB{
	meta:
		description = "Ransom:Win32/Balaclava.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,41 00 41 00 0c 00 00 0a 00 "
		
	strings :
		$a_81_0 = {54 6f 74 61 6c 46 69 6c 65 73 2e 74 78 74 } //0a 00  TotalFiles.txt
		$a_81_1 = {20 2f 63 20 64 65 6c 20 } //0a 00   /c del 
		$a_81_2 = {48 4f 57 5f 54 4f 5f 52 45 43 4f 56 45 52 59 5f 46 49 4c 45 53 2e 74 78 74 } //0a 00  HOW_TO_RECOVERY_FILES.txt
		$a_81_3 = {24 52 45 43 59 43 4c 45 2e 42 49 4e } //0a 00  $RECYCLE.BIN
		$a_81_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 57 } //0a 00  ShellExecuteExW
		$a_81_5 = {41 4c 4c 55 53 45 52 53 50 52 4f 46 49 4c 45 } //01 00  ALLUSERSPROFILE
		$a_81_6 = {41 76 61 73 74 } //01 00  Avast
		$a_81_7 = {41 76 69 72 61 } //01 00  Avira
		$a_81_8 = {43 4f 4d 4f 44 4f } //01 00  COMODO
		$a_81_9 = {44 72 2e 57 65 62 } //01 00  Dr.Web
		$a_81_10 = {4b 61 73 70 65 72 73 6b 79 20 4c 61 62 } //01 00  Kaspersky Lab
		$a_81_11 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 } //00 00  Internet Explorer
	condition:
		any of ($a_*)
 
}