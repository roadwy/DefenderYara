
rule TrojanDownloader_Win32_Banker_H{
	meta:
		description = "TrojanDownloader:Win32/Banker.H,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //01 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {64 69 6c 6d 61 2e 67 69 66 } //01 00  dilma.gif
		$a_01_2 = {6e 61 6d 6f 72 61 64 61 2e 67 69 66 } //01 00  namorada.gif
		$a_01_3 = {36 39 2e 36 34 2e 34 33 2e 31 32 39 } //01 00  69.64.43.129
		$a_01_4 = {69 70 61 64 63 6f 6e 66 2e 65 78 65 } //00 00  ipadconf.exe
	condition:
		any of ($a_*)
 
}