
rule TrojanDownloader_Win32_Exwamp_A{
	meta:
		description = "TrojanDownloader:Win32/Exwamp.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 77 61 6d 70 5c 77 77 77 5c 64 78 2d 65 78 70 6c 6f 69 74 5c } //1 \wamp\www\dx-exploit\
		$a_01_1 = {74 07 c1 cf 0d 01 c7 eb f2 3b 7c 24 14 75 e1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}