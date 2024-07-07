
rule Trojan_Win32_Zusy_GJU_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GJU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 f8 05 83 e6 1f c1 e6 06 03 34 85 90 01 04 8b 45 e4 8b 00 89 06 8d 46 0c 8a 03 88 46 04 68 a0 0f 00 00 50 90 00 } //10
		$a_01_1 = {40 2e 72 6f 70 66 } //1 @.ropf
		$a_01_2 = {5c 50 6f 73 74 49 6e 73 74 61 6c 6c 5c 72 65 6c 65 61 73 65 5c 50 6f 73 74 49 6e 73 74 61 6c 6c 2e 70 64 62 } //1 \PostInstall\release\PostInstall.pdb
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}