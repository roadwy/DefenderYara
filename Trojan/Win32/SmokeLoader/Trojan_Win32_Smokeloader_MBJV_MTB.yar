
rule Trojan_Win32_Smokeloader_MBJV_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.MBJV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff d3 80 04 3e ?? ff d3 80 34 3e ?? ff d3 ff d3 80 04 3e ?? ff d3 80 04 3e ?? 46 3b 74 24 ?? 0f } //1
		$a_03_1 = {ff d3 80 04 3e ?? ff d3 80 34 3e ?? ff d3 80 04 3e ?? ff d3 80 2c 3e ?? ff d3 80 04 3e ?? 46 3b 74 24 ?? 0f } //1
		$a_01_2 = {46 72 69 65 68 69 55 54 59 75 61 69 00 00 00 00 44 55 73 75 64 67 64 67 65 75 64 75 77 } //4
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*4) >=5
 
}