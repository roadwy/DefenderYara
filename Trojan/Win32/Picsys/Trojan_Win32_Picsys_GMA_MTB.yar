
rule Trojan_Win32_Picsys_GMA_MTB{
	meta:
		description = "Trojan:Win32/Picsys.GMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {16 80 34 01 c0 4e 47 4e 0e ba 90 01 04 e2 90 00 } //01 00 
		$a_80_1 = {54 4a 70 72 6f 6a 4d 61 69 6e } //TJprojMain  01 00 
		$a_01_2 = {40 2e 74 68 65 6d 69 64 61 } //00 00  @.themida
	condition:
		any of ($a_*)
 
}