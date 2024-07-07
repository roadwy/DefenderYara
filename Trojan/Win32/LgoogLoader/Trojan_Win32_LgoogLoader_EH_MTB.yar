
rule Trojan_Win32_LgoogLoader_EH_MTB{
	meta:
		description = "Trojan:Win32/LgoogLoader.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6f 00 6b 00 2e 00 74 00 78 00 74 00 } //1 ok.txt
		$a_01_1 = {30 00 2e 00 70 00 6e 00 67 00 } //1 0.png
		$a_01_2 = {6b 00 61 00 76 00 20 00 77 00 69 00 70 00 65 00 6c 00 20 00 6e 00 65 00 73 00 65 00 78 00 69 00 20 00 6a 00 69 00 6c 00 6f 00 76 00 2d 00 66 00 69 00 63 00 61 00 71 00 75 00 65 00 2e 00 2f 00 71 00 75 00 6f 00 77 00 61 00 20 00 76 00 69 00 73 00 6f 00 76 00 61 00 20 00 71 00 75 00 69 00 70 00 20 00 78 00 65 00 6c 00 6f 00 } //1 kav wipel nesexi jilov-ficaque./quowa visova quip xelo
		$a_01_3 = {47 65 74 46 69 6c 65 41 74 74 72 69 62 75 74 65 73 57 } //1 GetFileAttributesW
		$a_01_4 = {43 72 65 61 74 65 46 69 6c 65 57 } //1 CreateFileW
		$a_01_5 = {6e 61 64 69 71 75 65 2e 70 64 62 } //1 nadique.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}