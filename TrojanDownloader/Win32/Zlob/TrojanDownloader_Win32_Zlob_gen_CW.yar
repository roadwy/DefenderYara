
rule TrojanDownloader_Win32_Zlob_gen_CW{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!CW,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {e9 67 9f ff ff 30 30 30 31 65 63 32 64 30 30 30 30 30 30 30 36 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 } //1
		$a_01_1 = {68 2d 7a 6c 6c 53 74 7d 6e 67 ab a7 d7 0c ed b7 4c 61 79 4e 61 6d ef 96 df 03 6d 8e 18 7f 46 7c } //1
		$a_01_2 = {32 34 03 34 45 45 ad 7b a1 dd 0c bf 4e 00 7b 28 93 78 65 63 1b ad e1 f7 ee 68 03 63 74 2e 70 0b 72 65 5b 69 03 6b b1 ed bb 2f 08 70 3a 2f 2f 77 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}