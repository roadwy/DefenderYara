
rule TrojanDownloader_Win32_Unruy_Q{
	meta:
		description = "TrojanDownloader:Win32/Unruy.Q,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 c7 45 e0 42 4d c7 45 ea 36 00 00 00 ff 50 50 } //1
		$a_01_1 = {ff 90 8c 00 00 00 50 ff 16 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}