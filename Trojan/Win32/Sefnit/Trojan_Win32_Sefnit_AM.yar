
rule Trojan_Win32_Sefnit_AM{
	meta:
		description = "Trojan:Win32/Sefnit.AM,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {64 00 72 00 6d 00 6e 00 67 00 75 00 61 00 72 00 64 00 2e 00 63 00 6f 00 6d 00 2f 00 67 00 65 00 74 00 74 00 61 00 73 00 6b 00 73 00 2e 00 70 00 68 00 70 00 } //1 drmnguard.com/gettasks.php
		$a_01_1 = {76 00 69 00 72 00 74 00 67 00 75 00 61 00 72 00 64 00 2e 00 63 00 6f 00 6d 00 2f 00 67 00 65 00 74 00 74 00 61 00 73 00 6b 00 73 00 2e 00 70 00 68 00 70 00 } //1 virtguard.com/gettasks.php
		$a_01_2 = {6c 00 69 00 63 00 67 00 75 00 61 00 72 00 64 00 2e 00 63 00 6f 00 6d 00 2f 00 67 00 65 00 74 00 74 00 61 00 73 00 6b 00 73 00 2e 00 70 00 68 00 70 00 } //1 licguard.com/gettasks.php
		$a_01_3 = {62 61 63 6b 64 6f 6f 72 5c 72 65 6c 65 61 73 65 5c 6f 75 74 70 75 74 5c 4d 69 6e 53 69 7a 65 52 65 6c 5c 62 61 63 6b 64 6f 6f 72 2e 70 64 62 } //1 backdoor\release\output\MinSizeRel\backdoor.pdb
		$a_03_4 = {8d 45 f3 50 8d 45 f3 50 ff 75 e8 8d 4d d8 88 5d f3 e8 ?? ?? ?? ?? c6 45 fc 03 39 5d e8 74 1b 8d 45 ec 50 ff 75 e8 ff 75 d8 ff 76 08 } //1
		$a_03_5 = {8d 45 f3 50 ff 75 ec 8d 4d d8 88 5d f3 e8 ?? ?? ?? ?? 8b 85 ?? ?? 00 00 2b c3 74 3a 48 75 75 53 8d 45 e4 50 ff 75 ec 89 5d e4 ff 75 d8 ff 75 c8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}