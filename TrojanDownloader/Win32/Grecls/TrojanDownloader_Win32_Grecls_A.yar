
rule TrojanDownloader_Win32_Grecls_A{
	meta:
		description = "TrojanDownloader:Win32/Grecls.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b9 04 00 00 00 33 d2 8b 03 e8 90 01 02 ff ff 8b 85 90 01 01 ff ff ff ba 90 01 02 10 00 e8 90 01 02 ff ff 75 7a 8d 8d 90 01 01 ff ff ff ba 01 00 00 00 b8 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}