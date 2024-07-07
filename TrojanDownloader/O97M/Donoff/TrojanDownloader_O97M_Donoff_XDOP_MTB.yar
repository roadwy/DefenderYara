
rule TrojanDownloader_O97M_Donoff_XDOP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.XDOP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 74 78 67 76 63 69 2e 52 75 6e 28 71 68 74 75 6c 78 61 2c 20 63 70 77 72 63 76 69 6d 74 6e 6b 70 74 29 } //1 = txgvci.Run(qhtulxa, cpwrcvimtnkpt)
		$a_01_1 = {52 65 67 50 61 72 73 65 20 3d 20 2e 52 65 70 6c 61 63 65 28 6d 53 74 72 2c 20 22 24 31 22 29 } //1 RegParse = .Replace(mStr, "$1")
		$a_01_2 = {6d 53 74 72 20 3d 20 2e 45 78 65 63 75 74 65 28 68 74 6d 6c 29 28 30 29 } //1 mStr = .Execute(html)(0)
		$a_01_3 = {43 61 6c 6c 20 6b 6b 78 73 2e 75 6d 6e 70 7a 74 71 6f 79 74 67 6b 6f 6e 77 68 64 73 6f 62 } //1 Call kkxs.umnpztqoytgkonwhdsob
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}