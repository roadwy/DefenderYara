
rule TrojanDownloader_Win32_Kaiket_A{
	meta:
		description = "TrojanDownloader:Win32/Kaiket.A,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 } //01 00  SOFTWARE\Borland\Delphi
		$a_01_1 = {70 6f 70 73 2e 69 6d 67 73 65 72 76 65 72 2e 6b 72 2f 6b 61 69 2f 69 6e 73 74 61 6c 6c 2f 69 6e 73 74 61 6c 6c 5f 63 6f 75 6e 74 2e 70 68 70 } //01 00  pops.imgserver.kr/kai/install/install_count.php
		$a_01_2 = {70 6f 70 73 2e 69 6d 67 73 65 72 76 65 72 2e 6b 72 2f 6b 61 69 2f 69 6e 73 74 61 6c 6c 2f 75 70 64 61 74 65 2e 70 68 70 } //01 00  pops.imgserver.kr/kai/install/update.php
		$a_01_3 = {73 6f 66 74 77 61 72 65 5c 6b 61 69 5c 31 5c 6c 69 76 65 74 69 6d 65 } //01 00  software\kai\1\livetime
		$a_01_4 = {62 6c 6f 63 6b 2e 69 6e 74 72 69 63 68 2e 63 6f 6d 2f 62 6c 6f 63 6b } //01 00  block.intrich.com/block
		$a_01_5 = {6b 61 69 6b 65 74 2e 64 6c 6c } //00 00  kaiket.dll
	condition:
		any of ($a_*)
 
}