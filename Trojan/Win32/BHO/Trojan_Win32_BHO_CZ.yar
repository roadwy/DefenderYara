
rule Trojan_Win32_BHO_CZ{
	meta:
		description = "Trojan:Win32/BHO.CZ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {80 7d fe 00 74 30 83 7e 04 00 0f 95 c0 84 d8 74 18 ff 76 10 68 90 01 04 ff 75 f4 8d 45 f4 ba 03 00 00 00 90 00 } //1
		$a_00_1 = {49 45 28 41 4c 28 22 25 73 22 2c } //1 IE(AL("%s",
		$a_00_2 = {5c 5f 49 45 42 72 6f 77 73 65 72 48 65 6c 70 65 72 2e 70 61 73 } //1 \_IEBrowserHelper.pas
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 65 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 } //1 Software\Microsoft\Windows\CurrentVersion\explorer\Browser Helper Objects
		$a_00_4 = {74 6f 61 73 74 2e 64 75 6e 6f 2e 6b 72 2f 69 66 72 5f } //1 toast.duno.kr/ifr_
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}