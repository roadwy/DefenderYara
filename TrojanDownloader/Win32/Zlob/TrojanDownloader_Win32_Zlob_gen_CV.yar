
rule TrojanDownloader_Win32_Zlob_gen_CV{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!CV,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {fd 6f 0f b7 73 1e 6f 72 61 67 65 32 30 30 39 43 d6 de fe 1b 8d 62 6f 70 6c 61 79 65 72 2e c7 74 } //1
		$a_01_1 = {f6 0a 5f 76 2f 76 69 64 65 6f d6 0d 7b 27 56 0a 2f 27 74 6a 1f 16 fb ff 74 2f 3f 63 3d 25 31 2e 31 64 25 64 06 ef 53 70 79 d6 fd bb db 77 61 8b } //1
		$a_01_2 = {ff 87 00 90 00 6d 79 63 2e 69 63 6f 00 25 73 be fd ff ed 2f 64 6f 0a 70 68 70 3f 74 79 70 65 3d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}