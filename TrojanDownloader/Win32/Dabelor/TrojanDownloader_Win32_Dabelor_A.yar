
rule TrojanDownloader_Win32_Dabelor_A{
	meta:
		description = "TrojanDownloader:Win32/Dabelor.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c3 00 00 00 57 69 6e 64 6f 77 73 20 53 65 63 75 72 69 74 79 20 41 6c 65 72 74 00 00 53 83 c4 f8 } //1
		$a_01_1 = {ff ff ff ff 0a 00 00 00 6d 65 72 6d 61 6e 2e 65 78 65 00 00 ff ff ff ff 09 00 00 00 78 65 72 6f } //1
		$a_01_2 = {6c 00 00 00 ff ff ff ff 0b 00 00 00 6d 75 73 68 69 6d 75 2e 65 78 65 00 55 8b ec 33 c0 55 68 8c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}