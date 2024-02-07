
rule TrojanDownloader_Win32_Asnep_A{
	meta:
		description = "TrojanDownloader:Win32/Asnep.A,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 64 6e 66 2e 65 78 65 } //02 00  \dnf.exe
		$a_01_1 = {42 6c 61 63 6b 4d 6f 6f 6e 20 52 75 6e 54 69 6d 65 20 45 72 72 6f 72 3a } //02 00  BlackMoon RunTime Error:
		$a_01_2 = {43 6f 6e 74 65 6e 74 2d 54 72 61 6e 73 66 65 72 2d 45 6e 63 6f 64 69 6e 67 3a 20 62 61 73 65 36 34 } //05 00  Content-Transfer-Encoding: base64
		$a_01_3 = {2f 63 72 61 73 73 2e 65 78 65 } //05 00  /crass.exe
		$a_01_4 = {2f 73 79 73 74 65 72 6e 2e 62 69 6e } //05 00  /systern.bin
		$a_01_5 = {5c 73 76 63 68 6f 74 2e 65 78 65 } //05 00  \svchot.exe
		$a_01_6 = {35 31 38 70 65 6e 67 2e 63 6f 6d } //00 00  518peng.com
		$a_00_7 = {80 10 00 00 5e b2 1b ce 22 c0 } //f1 26 
	condition:
		any of ($a_*)
 
}