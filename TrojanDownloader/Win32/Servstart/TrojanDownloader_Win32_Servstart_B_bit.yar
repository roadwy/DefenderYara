
rule TrojanDownloader_Win32_Servstart_B_bit{
	meta:
		description = "TrojanDownloader:Win32/Servstart.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 45 c0 56 c6 45 c1 49 c6 45 c2 44 c6 45 c3 3a c6 45 c4 32 c6 45 c5 30 c6 45 c6 31 c6 45 c7 34 c6 45 c8 2d c6 45 c9 53 c6 45 ca 56 c6 45 cb 38 } //1
		$a_03_1 = {3b c6 7c e3 90 09 19 00 8b 90 01 02 8a 14 08 80 c2 7a 88 14 08 8b 90 01 02 8a 14 08 80 f2 90 01 01 88 14 08 40 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}