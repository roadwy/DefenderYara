
rule TrojanDownloader_Win32_Thoper_A{
	meta:
		description = "TrojanDownloader:Win32/Thoper.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_10_0 = {77 69 6e 73 76 63 66 73 } //1 winsvcfs
		$a_00_1 = {6a 5b 99 5f f7 ff 46 88 45 ff 3b 71 04 7c e5 5f } //1
	condition:
		((#a_10_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}