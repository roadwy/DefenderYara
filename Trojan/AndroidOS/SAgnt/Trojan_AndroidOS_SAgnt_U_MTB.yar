
rule Trojan_AndroidOS_SAgnt_U_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.U!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 61 64 6d 2f 73 63 61 66 66 6f 6c 64 2f 53 63 61 66 66 6f 6c 64 41 63 74 69 76 69 74 79 } //01 00  dadm/scaffold/ScaffoldActivity
		$a_01_1 = {2f 49 6e 73 74 61 6c 6c 65 72 52 65 73 74 61 72 74 65 72 53 65 72 76 69 63 65 } //01 00  /InstallerRestarterService
		$a_01_2 = {2f 57 6f 72 6b 65 72 41 63 63 65 73 73 69 62 69 6c 69 74 79 53 65 72 76 69 63 65 } //01 00  /WorkerAccessibilityService
		$a_01_3 = {2f 56 4e 43 41 63 74 69 76 69 74 79 } //01 00  /VNCActivity
		$a_01_4 = {67 65 74 52 6f 6f 74 49 6e 41 63 74 69 76 65 57 69 6e 64 6f 77 } //00 00  getRootInActiveWindow
	condition:
		any of ($a_*)
 
}