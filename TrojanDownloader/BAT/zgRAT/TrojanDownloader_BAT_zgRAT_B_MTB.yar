
rule TrojanDownloader_BAT_zgRAT_B_MTB{
	meta:
		description = "TrojanDownloader:BAT/zgRAT.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {61 6e 74 69 76 6d 6d } //02 00  antivmm
		$a_01_1 = {43 68 65 63 6b 46 6f 72 56 69 72 74 75 61 6c 4d 61 63 68 69 6e 65 } //01 00  CheckForVirtualMachine
		$a_01_2 = {47 65 74 44 65 6c 65 67 61 74 65 46 6f 72 46 75 6e 63 74 69 6f 6e 50 6f 69 6e 74 65 72 } //01 00  GetDelegateForFunctionPointer
		$a_01_3 = {47 65 74 50 72 6f 63 65 73 73 42 79 49 64 } //00 00  GetProcessById
	condition:
		any of ($a_*)
 
}