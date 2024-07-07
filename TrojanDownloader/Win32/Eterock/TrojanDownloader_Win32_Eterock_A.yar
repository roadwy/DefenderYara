
rule TrojanDownloader_Win32_Eterock_A{
	meta:
		description = "TrojanDownloader:Win32/Eterock.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //1 \svchost.exe
		$a_01_1 = {5c 00 54 00 61 00 73 00 6b 00 53 00 63 00 68 00 65 00 64 00 75 00 6c 00 65 00 72 00 } //1 \TaskScheduler
		$a_01_2 = {46 00 69 00 6e 00 69 00 73 00 68 00 65 00 64 00 20 00 4d 00 6b 00 44 00 69 00 72 00 20 00 54 00 65 00 6d 00 70 00 } //1 Finished MkDir Temp
		$a_01_3 = {5c 00 72 00 65 00 71 00 75 00 69 00 72 00 65 00 64 00 2e 00 67 00 6c 00 6f 00 } //1 \required.glo
		$a_01_4 = {5c 00 64 00 6f 00 74 00 6e 00 65 00 74 00 66 00 78 00 2e 00 65 00 78 00 65 00 20 00 2f 00 71 00 3a 00 61 00 20 00 2f 00 63 00 3a 00 } //1 \dotnetfx.exe /q:a /c:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}