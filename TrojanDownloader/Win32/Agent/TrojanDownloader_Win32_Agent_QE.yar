
rule TrojanDownloader_Win32_Agent_QE{
	meta:
		description = "TrojanDownloader:Win32/Agent.QE,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {5c 69 6e 65 74 63 2e 64 6c 6c } //1 \inetc.dll
		$a_02_1 = {2e 77 67 65 74 74 2e 63 6f 2e 63 63 2f [0-10] 2e 70 68 70 } //1
		$a_00_2 = {74 6f 6b 65 6e 3d } //1 token=
		$a_00_3 = {2f 53 49 4c 45 4e 54 } //1 /SILENT
		$a_00_4 = {2e 65 78 65 22 20 2f 53 } //1 .exe" /S
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule TrojanDownloader_Win32_Agent_QE_2{
	meta:
		description = "TrojanDownloader:Win32/Agent.QE,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_01_0 = {23 5c 4f 66 66 65 72 42 6f 78 5c 63 6f 6e 66 69 67 2e 78 6d 6c } //10 #\OfferBox\config.xml
		$a_00_1 = {2f 74 72 61 63 6b 73 74 61 74 73 2e 70 68 70 00 69 64 3d 31 26 74 6f 6b 65 6e 3d } //1
		$a_01_2 = {5c 4f 42 2e 65 78 65 } //1 \OB.exe
		$a_00_3 = {5c 63 6f 75 6e 74 5f 74 6f 74 61 6c 2e 74 78 74 00 68 74 74 70 3a } //1 捜畯瑮瑟瑯污琮瑸栀瑴㩰
		$a_00_4 = {2e 75 7a 34 2e 6e 65 74 2f 6c 6f 67 33 34 37 35 36 2e 70 68 70 } //1 .uz4.net/log34756.php
	condition:
		((#a_01_0  & 1)*10+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=12
 
}