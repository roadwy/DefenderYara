
rule TrojanDownloader_Win32_Small_AHR{
	meta:
		description = "TrojanDownloader:Win32/Small.AHR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 64 64 2e 69 70 33 33 30 33 33 2e 63 6f 6d } //01 00 
		$a_01_1 = {4e 59 30 37 48 6b 54 4a 6c 74 70 76 73 4d 61 31 48 6d 58 4f 47 63 35 6c 46 6d 2b 32 57 55 52 4d 48 63 6b 4e 4f 57 30 57 48 77 77 66 } //01 00 
		$a_01_2 = {25 73 4f 6e 65 47 25 64 2e 65 78 65 } //01 00 
		$a_01_3 = {85 c0 75 69 8d 45 a8 c6 45 f0 43 50 8d 85 a4 fe ff ff 50 8d 45 ac 50 8d 45 f0 53 50 ff 75 b0 c6 45 f1 6f c6 45 f2 6d c6 45 f3 70 c6 45 f4 75 c6 45 f5 74 c6 45 f6 65 c6 45 f7 72 c6 45 f8 4e c6 45 f9 61 c6 45 fa 6d c6 45 fb 65 88 5d fc ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}