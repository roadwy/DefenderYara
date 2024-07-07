
rule PWS_BAT_Stealer_HLAY_MTB{
	meta:
		description = "PWS:BAT/Stealer.HLAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 04 00 00 "
		
	strings :
		$a_81_0 = {57 72 69 74 65 41 6c 6c 42 79 74 65 73 } //4 WriteAllBytes
		$a_81_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //4 DownloadData
		$a_01_2 = {6d 00 69 00 6d 00 69 00 2e 00 65 00 78 00 65 00 } //5 mimi.exe
		$a_01_3 = {73 00 74 00 64 00 65 00 72 00 72 00 2e 00 70 00 6c 00 2f 00 6d 00 69 00 6d 00 69 00 2f 00 6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 2e 00 65 00 78 00 65 00 } //5 stderr.pl/mimi/mimikatz.exe
	condition:
		((#a_81_0  & 1)*4+(#a_81_1  & 1)*4+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5) >=18
 
}