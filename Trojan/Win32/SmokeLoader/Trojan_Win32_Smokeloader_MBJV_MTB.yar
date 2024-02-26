
rule Trojan_Win32_Smokeloader_MBJV_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.MBJV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff d3 80 04 3e 90 01 01 ff d3 80 34 3e 90 01 01 ff d3 ff d3 80 04 3e 90 01 01 ff d3 80 04 3e 90 01 01 46 3b 74 24 90 01 01 0f 90 00 } //01 00 
		$a_03_1 = {ff d3 80 04 3e 90 01 01 ff d3 80 34 3e 90 01 01 ff d3 80 04 3e 90 01 01 ff d3 80 2c 3e 90 01 01 ff d3 80 04 3e 90 01 01 46 3b 74 24 90 01 01 0f 90 00 } //04 00 
		$a_01_2 = {46 72 69 65 68 69 55 54 59 75 61 69 00 00 00 00 44 55 73 75 64 67 64 67 65 75 64 75 77 } //00 00 
	condition:
		any of ($a_*)
 
}