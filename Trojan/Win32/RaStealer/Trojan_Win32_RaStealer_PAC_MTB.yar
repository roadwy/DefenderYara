
rule Trojan_Win32_RaStealer_PAC_MTB{
	meta:
		description = "Trojan:Win32/RaStealer.PAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c1 8b 4d 90 01 01 fe c3 8b 09 03 ca 0f b6 d3 8d 14 96 89 55 ec 47 83 45 0c 90 01 01 89 0a eb b3 23 4d f0 8b 55 f8 8b 0c 11 90 00 } //1
		$a_03_1 = {fe c3 8b c1 0f b6 cb 8d 14 8e 8b 4d 0c 89 55 ec 8b 09 eb 90 01 01 8b 55 f4 8b c1 8b 4d 0c fe c3 8b 09 03 ca 0f b6 d3 8d 14 96 89 55 ec 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}