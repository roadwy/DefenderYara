
rule TrojanDropper_O97M_Obfuse_PDA_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.PDA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 73 67 42 6f 78 20 22 65 72 72 6f 72 21 20 52 65 2d 69 6e 73 74 61 6c 6c 20 6f 66 66 69 63 65 } //01 00  MsgBox "error! Re-install office
		$a_01_1 = {47 65 74 28 61 73 6b 6a 64 6a 61 77 6a 6b 64 6f 6b 61 77 6f 64 29 20 5f } //01 00  Get(askjdjawjkdokawod) _
		$a_01_2 = {47 65 74 4f 62 6a 65 63 74 28 6b 6f 61 6b 6f 73 64 6b 29 20 5f } //01 00  GetObject(koakosdk) _
		$a_01_3 = {27 32 57 6a 54 67 68 57 27 2c 27 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 53 74 61 72 74 75 70 27 2c 27 33 35 35 31 35 35 36 41 43 66 67 6d 73 27 2c 27 43 6f 70 79 46 69 6c 65 27 2c 27 31 39 30 32 39 35 34 76 79 6c 63 7a 4e 27 2c 27 47 65 74 27 2c 27 37 64 6d 76 47 4d 52 27 2c 27 53 68 6f 77 57 69 6e 64 6f 77 27 2c 27 31 35 35 73 42 7a 68 66 62 27 2c 27 77 69 6e 6d 67 6d 74 73 3a 27 } //01 00  '2WjTghW','Win32_ProcessStartup','3551556ACfgms','CopyFile','1902954vylczN','Get','7dmvGMR','ShowWindow','155sBzhfb','winmgmts:'
		$a_03_4 = {43 3a 5c 78 35 63 50 72 6f 67 72 61 6d 44 61 74 61 5c 78 35 63 64 64 6f 6e 64 2e 63 6f 6d 5c 78 32 30 68 74 74 70 73 3a 2f 2f 77 77 77 2e 6d 65 64 69 61 66 69 72 65 2e 63 6f 6d 2f 66 69 6c 65 2f 90 02 20 2f 90 02 02 2e 68 74 6d 2f 66 69 6c 65 90 00 } //01 00 
		$a_01_5 = {27 70 75 73 68 27 5d 28 5f 30 78 66 66 31 31 66 65 5b 27 73 68 69 66 74 27 5d 28 29 29 3b 7d 63 61 74 63 68 28 5f 30 78 35 38 39 62 36 61 29 } //01 00  'push'](_0xff11fe['shift']());}catch(_0x589b6a)
		$a_01_6 = {43 72 65 61 74 65 20 28 22 77 73 63 72 69 70 74 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 75 70 64 61 74 65 2e 6a 73 22 29 } //00 00  Create ("wscript C:\Users\Public\update.js")
	condition:
		any of ($a_*)
 
}