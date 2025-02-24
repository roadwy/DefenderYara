
rule Trojan_Win32_Zusy_GTM_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {4b 65 95 ef 60 b4 5a 30 28 ed 61 51 ea } //10
		$a_80_1 = {54 4a 70 72 6f 6a 4d 61 69 6e 2e 65 78 65 } //TJprojMain.exe  1
	condition:
		((#a_01_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}
rule Trojan_Win32_Zusy_GTM_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.GTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 4c 05 ?? 8d 34 71 33 75 ?? 40 83 f8 } //5
		$a_03_1 = {8a 44 0d d4 32 04 3a 32 c2 41 83 f9 ?? 88 04 3a ?? ?? 33 c9 42 3b d6 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}