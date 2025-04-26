
rule PWS_Win32_QQpass_CV{
	meta:
		description = "PWS:Win32/QQpass.CV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 71 71 39 39 34 34 35 35 2e 63 6f 6d 2f [0-20] 2f 71 71 70 6f 73 74 2e 61 73 70 00 26 71 71 70 61 73 73 77 6f 72 64 3d 00 3f 71 71 6e 75 6d 62 65 72 3d 00 } //1
		$a_03_1 = {68 0b 00 01 16 68 01 00 01 52 e8 ?? ?? ?? ?? 83 c4 10 89 45 f8 8d 45 f8 50 8d 45 fc 50 b8 ?? ?? ?? ?? 89 45 f4 8d 45 f4 50 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}