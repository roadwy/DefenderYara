
rule Trojan_Win32_Zusy_BQ_MTB{
	meta:
		description = "Trojan:Win32/Zusy.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {42 73 6f 68 6a 69 72 6a 41 75 66 69 73 65 69 67 68 6a 73 65 69 68 } //02 00  BsohjirjAufiseighjseih
		$a_01_1 = {4d 73 68 69 72 41 69 6a 73 65 69 68 6a 65 72 68 } //02 00  MshirAijseihjerh
		$a_01_2 = {4f 73 6f 6a 67 65 69 68 65 72 41 69 6a 73 65 69 6a 65 68 } //01 00  OsojgeiherAijseijeh
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //00 00  WaitForSingleObject
	condition:
		any of ($a_*)
 
}