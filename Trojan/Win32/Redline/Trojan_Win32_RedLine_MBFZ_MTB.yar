
rule Trojan_Win32_RedLine_MBFZ_MTB{
	meta:
		description = "Trojan:Win32/RedLine.MBFZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 1c 01 6c 24 10 03 fa d3 ea 89 7c 24 24 89 54 24 14 8b 44 24 34 01 44 24 14 8b 44 24 24 31 44 24 10 8b 4c 24 10 33 4c 24 14 8d 44 24 28 89 4c 24 10 } //01 00 
		$a_01_1 = {69 00 78 00 65 00 6d 00 61 00 79 00 69 00 6e 00 6f 00 72 00 6f 00 20 00 72 00 69 00 76 00 65 00 72 00 6f 00 63 00 69 00 78 } //00 00 
	condition:
		any of ($a_*)
 
}