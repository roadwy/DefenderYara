
rule TrojanDownloader_Win64_Rugmi_AA_MTB{
	meta:
		description = "TrojanDownloader:Win64/Rugmi.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_01_0 = {55 3a 5c 72 6f 75 74 5c 78 36 34 5c 72 65 6c 65 61 73 65 5c 35 62 43 5c 61 32 6a 5c 6c 6c 71 2e 70 64 62 } //10 U:\rout\x64\release\5bC\a2j\llq.pdb
		$a_01_1 = {54 00 77 00 65 00 61 00 6b 00 53 00 63 00 68 00 65 00 64 00 75 00 6c 00 65 00 72 00 } //1 TweakScheduler
		$a_01_2 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 62 00 69 00 74 00 73 00 75 00 6d 00 2e 00 63 00 6f 00 6d 00 2f 00 63 00 68 00 65 00 63 00 6b 00 2e 00 70 00 68 00 70 00 } //1 https://bitsum.com/check.php
		$a_01_3 = {70 00 72 00 6f 00 6c 00 61 00 73 00 73 00 6f 00 2e 00 6b 00 65 00 79 00 } //1 prolasso.key
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}