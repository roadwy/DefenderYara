
rule TrojanDownloader_Win32_Emurbo_A{
	meta:
		description = "TrojanDownloader:Win32/Emurbo.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 00 53 00 42 00 69 00 74 00 73 00 00 00 00 00 ff ff ff ff 04 00 00 00 2e 64 6c 6c 00 00 00 00 55 } //1
		$a_01_1 = {2f 63 20 64 65 6c 20 00 20 3e 3e 20 4e 55 4c 00 43 6f 6d 53 70 65 63 00 55 } //1
		$a_01_2 = {68 74 74 70 3a 2f 2f 66 6c 79 63 6f 64 65 63 73 2e 63 6f 6d 2f } //1 http://flycodecs.com/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}