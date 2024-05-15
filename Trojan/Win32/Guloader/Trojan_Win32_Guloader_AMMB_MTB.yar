
rule Trojan_Win32_Guloader_AMMB_MTB{
	meta:
		description = "Trojan:Win32/Guloader.AMMB!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 00 61 00 72 00 61 00 6d 00 65 00 6e 00 69 00 61 00 20 00 6b 00 75 00 6c 00 64 00 20 00 6d 00 61 00 73 00 74 00 65 00 72 00 77 00 6f 00 72 00 6b 00 } //01 00  paramenia kuld masterwork
		$a_01_1 = {66 00 61 00 72 00 65 00 73 00 6f 00 65 00 6e 00 } //01 00  faresoen
		$a_01_2 = {74 00 69 00 6c 00 6d 00 65 00 6c 00 64 00 65 00 20 00 66 00 6f 00 6e 00 64 00 73 00 73 00 79 00 73 00 74 00 65 00 6d 00 65 00 72 00 6e 00 65 00 } //00 00  tilmelde fondssystemerne
	condition:
		any of ($a_*)
 
}