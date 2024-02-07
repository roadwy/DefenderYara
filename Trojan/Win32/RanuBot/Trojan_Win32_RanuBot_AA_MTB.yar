
rule Trojan_Win32_RanuBot_AA_MTB{
	meta:
		description = "Trojan:Win32/RanuBot.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 7a 56 77 33 39 79 6a 46 34 52 66 73 56 63 67 6d 69 36 63 2f 65 59 72 61 68 77 66 69 4c 57 72 6c 50 5f 75 67 2d 4b 42 4d 2f 6e 75 4f 43 6d 50 4b 46 4f 47 32 42 47 59 48 62 75 31 65 41 2f 4e 67 72 78 65 49 52 4a 52 42 4f 4b 6b 7a 73 5f 56 6d 46 4d } //00 00  OzVw39yjF4RfsVcgmi6c/eYrahwfiLWrlP_ug-KBM/nuOCmPKFOG2BGYHbu1eA/NgrxeIRJRBOKkzs_VmFM
	condition:
		any of ($a_*)
 
}