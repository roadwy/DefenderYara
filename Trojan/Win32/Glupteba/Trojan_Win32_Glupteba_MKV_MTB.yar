
rule Trojan_Win32_Glupteba_MKV_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ee 03 74 24 90 01 01 8b 44 24 90 01 01 31 44 24 10 81 3d 90 01 08 75 90 01 01 53 53 53 ff 15 90 01 04 8b 44 24 10 33 c6 89 44 24 10 2b f8 8b 44 24 38 29 44 24 14 83 6c 24 90 01 02 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_MKV_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 8b cb 8d 44 24 90 01 01 89 54 24 90 01 01 e8 90 01 04 8b 44 24 90 01 01 31 44 24 90 01 01 8b 44 24 90 01 01 8b 4c 24 90 01 01 50 51 8d 54 24 90 01 01 52 e8 90 01 04 8b 44 24 90 01 01 50 8b c6 e8 90 01 04 81 44 24 90 01 05 83 6c 24 90 01 02 8b f0 89 74 24 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}