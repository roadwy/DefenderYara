
rule TrojanDownloader_O97M_EncDoc_PKY_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PKY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {65 72 6d 6b 64 66 28 29 2e 45 78 65 63 20 45 72 66 6d 66 6b 65 28 29 } //1 ermkdf().Exec Erfmfke()
		$a_01_1 = {3d 20 52 61 6e 67 65 28 70 4e 46 61 4f 72 4e 62 6c 66 66 29 2e 56 61 6c 75 65 } //1 = Range(pNFaOrNblff).Value
		$a_01_2 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 65 72 6d 6b 64 73 66 73 28 29 29 } //1 = GetObject(ermkdsfs())
		$a_01_3 = {3d 20 68 4a 52 6a 48 49 77 55 28 22 42 32 30 30 22 29 20 2b 20 68 4a 52 6a 48 49 77 55 28 22 42 32 30 35 22 29 20 2b 20 68 4a 52 6a 48 49 77 55 28 22 42 32 30 37 22 29 20 2b 20 68 4a 52 6a 48 49 77 55 28 22 42 32 30 38 22 29 20 2b 20 22 20 2d 57 69 6e 64 22 20 2b 20 22 6f 77 53 74 22 20 2b 20 22 79 6c 65 20 48 69 64 22 20 2b 20 22 64 65 6e 20 22 20 2b 20 68 4a 52 6a 48 49 77 55 28 22 42 31 30 30 22 29 } //1 = hJRjHIwU("B200") + hJRjHIwU("B205") + hJRjHIwU("B207") + hJRjHIwU("B208") + " -Wind" + "owSt" + "yle Hid" + "den " + hJRjHIwU("B100")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}