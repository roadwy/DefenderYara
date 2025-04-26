
rule TrojanDownloader_Win32_Servstart_C_bit{
	meta:
		description = "TrojanDownloader:Win32/Servstart.C!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 44 24 0c 6d c6 44 24 0d 79 c6 44 24 0e 73 c6 44 24 0f 71 88 4c 24 11 c6 44 24 12 2e 88 4c 24 13 c6 44 24 16 00 } //1
		$a_01_1 = {c6 45 f1 53 c6 45 f2 53 c6 45 f3 53 c6 45 f4 53 c6 45 f5 53 c6 45 f6 56 c6 45 f7 49 c6 45 f8 44 } //1
		$a_01_2 = {68 74 74 70 3a 2f 2f 68 61 63 6b 62 6f 78 2e 66 33 33 32 32 2e 6f 72 67 3a 38 30 38 2f 43 6f 6e 73 79 73 32 31 2e 64 6c 6c } //1 http://hackbox.f3322.org:808/Consys21.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}