
rule TrojanProxy_Win32_Frentyks_A{
	meta:
		description = "TrojanProxy:Win32/Frentyks.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 00 73 00 74 00 68 00 2e 00 64 00 6c 00 6c 00 } //1 dsth.dll
		$a_01_1 = {26 00 61 00 5f 00 66 00 3d 00 66 00 6f 00 72 00 75 00 6d 00 } //1 &a_f=forum
		$a_01_2 = {61 63 63 64 5f 66 61 6b 65 } //1 accd_fake
		$a_01_3 = {73 6b 79 6e 65 74 } //1 skynet
		$a_01_4 = {34 6a 68 6e 53 48 38 44 65 6b 53 32 62 33 35 46 62 33 4e 68 64 41 52 4e 33 4b 37 75 4d 48 75 42 4f 2f 43 63 6e 41 59 37 78 67 4d 3d } //1 4jhnSH8DekS2b35Fb3NhdARN3K7uMHuBO/CcnAY7xgM=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
rule TrojanProxy_Win32_Frentyks_A_2{
	meta:
		description = "TrojanProxy:Win32/Frentyks.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {4e 00 54 00 49 00 4f 00 4e 00 45 00 54 00 36 00 2e 00 53 00 59 00 53 00 } //1 NTIONET6.SYS
		$a_01_1 = {77 00 75 00 73 00 61 00 33 00 32 00 2e 00 65 00 78 00 65 00 } //1 wusa32.exe
		$a_01_2 = {64 00 73 00 74 00 68 00 2e 00 64 00 6c 00 6c 00 } //1 dsth.dll
		$a_01_3 = {69 00 6e 00 73 00 74 00 2e 00 7a 00 69 00 70 00 } //1 inst.zip
		$a_01_4 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 5f 00 63 00 2e 00 70 00 68 00 70 00 3f 00 } //1 download_c.php?
		$a_01_5 = {53 00 79 00 73 00 74 00 65 00 6d 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 41 00 64 00 76 00 61 00 6e 00 63 00 65 00 64 00 56 00 69 00 65 00 77 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 SystemPropertiesAdvancedViewer.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}