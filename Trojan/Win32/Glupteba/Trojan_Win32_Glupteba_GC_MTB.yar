
rule Trojan_Win32_Glupteba_GC_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 ff 69 04 00 00 75 90 01 07 ff d5 90 01 0a e8 90 01 04 30 04 1e 46 3b f7 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_GC_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 45 7c 8b 8d 90 02 20 89 78 90 02 20 89 08 90 00 } //01 00 
		$a_02_1 = {8b cf c1 e9 90 01 01 03 8d 90 02 20 03 85 90 02 20 89 35 90 02 20 33 c1 8b 8d 90 02 20 03 cf 33 c1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}