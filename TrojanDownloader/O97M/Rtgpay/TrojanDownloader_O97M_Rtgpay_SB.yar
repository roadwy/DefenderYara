
rule TrojanDownloader_O97M_Rtgpay_SB{
	meta:
		description = "TrojanDownloader:O97M/Rtgpay.SB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {65 78 65 2e 53 47 54 52 2f 6d 72 6f 66 2f 6d 6f 63 2e 72 75 6f 74 79 63 69 6c 6f 70 2f 2f 3a 70 74 74 68 } //1 exe.SGTR/mrof/moc.ruotycilop//:ptth
		$a_00_1 = {26 20 53 74 72 52 65 76 65 72 73 65 28 22 65 78 65 2e 7a 77 78 72 6d 33 6a 6f 22 29 } //1 & StrReverse("exe.zwxrm3jo")
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}