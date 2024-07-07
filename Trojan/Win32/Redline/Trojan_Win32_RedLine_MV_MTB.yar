
rule Trojan_Win32_RedLine_MV_MTB{
	meta:
		description = "Trojan:Win32/RedLine.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 03 45 e8 89 45 08 8b 45 f4 03 45 f8 89 45 fc 83 0d 0c 58 45 00 ff 8b c7 c1 e8 05 c7 05 90 01 08 89 45 0c 8b 45 e0 01 45 0c 8b 45 fc 31 45 08 8b 45 0c 31 45 08 ff 75 08 8d 45 f0 50 e8 90 01 04 81 45 f8 90 01 04 ff 4d ec 8b 45 f0 0f 85 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}