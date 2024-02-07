
rule Trojan_Win32_Babar_GMC_MTB{
	meta:
		description = "Trojan:Win32/Babar.GMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {22 db 1f 89 c4 22 11 91 32 22 20 5b 02 d3 49 dc 8e f5 } //01 00 
		$a_01_1 = {40 2e 76 6d 70 30 } //01 00  @.vmp0
		$a_01_2 = {78 75 6e 69 30 30 41 30 75 6e 69 30 45 30 31 75 6e 69 } //00 00  xuni00A0uni0E01uni
	condition:
		any of ($a_*)
 
}