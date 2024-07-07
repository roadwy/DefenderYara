
rule TrojanDownloader_Win32_Kepier_A_bit{
	meta:
		description = "TrojanDownloader:Win32/Kepier.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 63 65 73 73 53 61 66 65 2e 65 78 65 } //1 ProcessSafe.exe
		$a_03_1 = {68 74 74 70 3a 2f 2f 90 02 30 2f 74 6f 6e 67 6a 69 2e 70 68 70 3f 75 69 64 3d 90 00 } //1
		$a_01_2 = {53 45 4c 45 43 54 20 4e 61 6d 65 20 46 52 4f 4d 20 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 20 57 68 65 72 65 20 4e 61 6d 65 3d 22 25 73 22 } //1 SELECT Name FROM Win32_Process Where Name="%s"
		$a_01_3 = {2e 70 62 69 70 6b 69 65 72 72 71 6f 6d 2e 6c 69 66 65 2f 6d 2f 75 61 63 2e 6a 70 67 } //1 .pbipkierrqom.life/m/uac.jpg
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}