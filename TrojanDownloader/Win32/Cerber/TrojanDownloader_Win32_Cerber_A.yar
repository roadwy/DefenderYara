
rule TrojanDownloader_Win32_Cerber_A{
	meta:
		description = "TrojanDownloader:Win32/Cerber.A,SIGNATURE_TYPE_PEHSTR_EXT,29 00 15 00 06 00 00 "
		
	strings :
		$a_01_0 = {75 67 67 63 3a 2f 2f } //10 uggc://
		$a_01_1 = {2e 72 6b 72 00 } //10
		$a_01_2 = {6a 76 61 76 61 72 67 } //10 jvavarg
		$a_01_3 = {54 72 67 47 72 7a 63 43 6e 67 75 4e } //10 TrgGrzcCnguN
		$a_01_4 = {77 69 6e 64 72 76 33 32 2e 65 78 65 } //1 windrv32.exe
		$a_01_5 = {77 69 6e 6d 67 72 2e 65 78 65 } //1 winmgr.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=21
 
}