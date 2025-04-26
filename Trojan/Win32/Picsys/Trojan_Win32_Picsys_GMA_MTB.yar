
rule Trojan_Win32_Picsys_GMA_MTB{
	meta:
		description = "Trojan:Win32/Picsys.GMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 80 34 01 c0 4e 47 4e 0e ba ?? ?? ?? ?? e2 } //10
		$a_80_1 = {54 4a 70 72 6f 6a 4d 61 69 6e } //TJprojMain  1
		$a_01_2 = {40 2e 74 68 65 6d 69 64 61 } //1 @.themida
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}