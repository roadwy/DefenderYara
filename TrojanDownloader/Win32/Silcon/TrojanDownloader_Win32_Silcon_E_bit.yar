
rule TrojanDownloader_Win32_Silcon_E_bit{
	meta:
		description = "TrojanDownloader:Win32/Silcon.E!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 c0 04 2b 05 90 01 04 2b 05 90 01 04 03 05 90 01 04 03 05 90 01 04 2b 05 90 01 04 03 05 90 01 04 ab 81 fe 90 01 04 7c 90 09 0d 00 ad 33 05 90 01 04 03 05 90 00 } //1
		$a_03_1 = {6a 00 ff d0 50 8f 05 90 01 04 c3 90 09 24 00 52 68 90 01 04 ff 15 90 01 04 50 ff 15 90 01 04 be 90 01 04 56 b9 90 01 04 51 68 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}