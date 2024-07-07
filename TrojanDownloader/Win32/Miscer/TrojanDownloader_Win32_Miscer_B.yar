
rule TrojanDownloader_Win32_Miscer_B{
	meta:
		description = "TrojanDownloader:Win32/Miscer.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {7a 63 79 5f 63 6c 69 63 6b } //1 zcy_click
		$a_01_1 = {7a 00 63 00 79 00 67 00 6f 00 2e 00 61 00 73 00 70 00 3f 00 7a 00 63 00 79 00 7a 00 7a 00 7a 00 6d 00 3d 00 7a 00 63 00 79 00 7a 00 7a 00 7a 00 6d 00 63 00 68 00 61 00 6b 00 61 00 6e 00 } //1 zcygo.asp?zcyzzzm=zcyzzzmchakan
		$a_01_2 = {53 00 43 00 48 00 30 00 53 00 54 00 53 00 2e 00 65 00 78 00 65 00 } //1 SCH0STS.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}