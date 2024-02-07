
rule TrojanDownloader_O97M_AsyncRat_SS_MTB{
	meta:
		description = "TrojanDownloader:O97M/AsyncRat.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 41 41 6b 41 47 59 41 5a 41 42 7a 41 47 59 41 63 77 42 6b 41 47 59 41 49 41 41 39 41 43 41 41 49 67 42 6d 41 48 4d 41 5a 67 42 6b 41 47 63 41 61 41 42 6d 41 47 51 41 5a 41 42 6d 41 47 63 41 } //01 00  IAAkAGYAZABzAGYAcwBkAGYAIAA9ACAAIgBmAHMAZgBkAGcAaABmAGQAZABmAGcA
		$a_01_1 = {53 65 74 20 5a 70 58 63 6d 73 43 51 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00  Set ZpXcmsCQ = CreateObject("Wscript.Shell")
		$a_01_2 = {5a 70 58 63 6d 73 43 51 2e 52 75 6e 20 72 64 65 41 6a 6e 73 68 76 20 2b 20 6c 71 66 61 64 55 4d 57 20 2b 20 41 4b 72 44 73 78 69 6f 43 2c 20 52 56 61 6c 75 65 } //00 00  ZpXcmsCQ.Run rdeAjnshv + lqfadUMW + AKrDsxioC, RValue
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}