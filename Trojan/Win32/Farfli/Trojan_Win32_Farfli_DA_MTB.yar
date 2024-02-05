
rule Trojan_Win32_Farfli_DA_MTB{
	meta:
		description = "Trojan:Win32/Farfli.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 74 8a 14 08 80 f2 62 88 14 08 40 3b c5 72 } //01 00 
		$a_01_1 = {33 36 30 5c 33 36 30 53 61 66 65 5c 53 42 33 36 30 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Farfli_DA_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.DA!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {b9 01 00 00 00 66 3b cb 75 02 33 db 80 04 3e 86 6a 00 ff d5 6a 00 ff d5 6a 00 ff d5 0f b7 d3 8a 44 54 14 30 04 3e 46 43 3b 74 24 10 7c d2 } //00 00 
	condition:
		any of ($a_*)
 
}