
rule Trojan_Win32_Picsys_GMC_MTB{
	meta:
		description = "Trojan:Win32/Picsys.GMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_01_0 = {1b 06 00 01 b4 27 20 24 9a 26 0e 63 09 30 1e 22 a3 3c e0 1b d2 45 30 08 0c 70 5e 59 } //10
		$a_01_1 = {2e 69 6d 70 6f 72 74 73 } //1 .imports
		$a_01_2 = {40 2e 74 68 65 6d 69 64 61 } //1 @.themida
		$a_80_3 = {54 4a 70 72 6f 6a 4d 61 69 6e 2e 65 78 65 } //TJprojMain.exe  1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_80_3  & 1)*1) >=13
 
}