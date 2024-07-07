
rule Trojan_Win32_AntiAV_BT_MTB{
	meta:
		description = "Trojan:Win32/AntiAV.BT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {4d 41 49 4e 49 43 4f 4e 2e 6c 6e 6b } //1 MAINICON.lnk
		$a_01_1 = {73 00 79 00 73 00 2e 00 6b 00 65 00 79 00 } //1 sys.key
		$a_01_2 = {47 00 46 00 49 00 52 00 65 00 73 00 74 00 61 00 72 00 74 00 33 00 32 00 2e 00 65 00 78 00 65 00 } //1 GFIRestart32.exe
		$a_01_3 = {5a 00 68 00 75 00 44 00 6f 00 6e 00 67 00 46 00 61 00 6e 00 67 00 59 00 75 00 2e 00 65 00 78 00 65 00 } //1 ZhuDongFangYu.exe
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 54 65 6e 63 65 6e 74 5c 50 6c 75 67 69 6e 5c 56 41 53 } //1 Software\Tencent\Plugin\VAS
		$a_01_5 = {5b 00 6e 00 75 00 6d 00 6c 00 6f 00 63 00 6b 00 5d 00 } //1 [numlock]
		$a_01_6 = {5b 00 72 00 61 00 6c 00 74 00 5d 00 } //1 [ralt]
		$a_01_7 = {5b 00 65 00 6e 00 74 00 65 00 72 00 5d 00 } //1 [enter]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}