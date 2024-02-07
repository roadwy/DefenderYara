
rule Backdoor_Linux_PoshPyReShell_C_{
	meta:
		description = "Backdoor:Linux/PoshPyReShell.C!!PoshPyReShell.C,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_81_0 = {57 6e 2f 58 36 74 6c 53 65 35 32 52 65 33 57 58 5a 6c 33 4d 79 31 6d 77 30 33 4b 45 42 63 43 71 2f 71 57 2f 65 2f 4e 73 63 68 6b } //01 00  Wn/X6tlSe52Re3WXZl3My1mw03KEBcCq/qW/e/Nschk
		$a_81_1 = {6b 64 6e 3d 74 69 6d 65 2e 73 74 72 70 74 69 6d 65 28 } //00 00  kdn=time.strptime(
	condition:
		any of ($a_*)
 
}