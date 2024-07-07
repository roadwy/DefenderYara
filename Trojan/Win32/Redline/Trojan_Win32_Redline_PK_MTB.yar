
rule Trojan_Win32_Redline_PK_MTB{
	meta:
		description = "Trojan:Win32/Redline.PK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 c1 e1 04 03 4d ec 03 c3 33 c1 33 45 fc 89 45 0c 8b 45 0c 01 05 90 01 04 8b 45 0c 29 45 08 8b 45 08 c1 e0 04 03 c7 89 45 f4 8b 45 08 03 45 f8 89 45 fc 8b 45 08 83 0d 90 01 05 c1 e8 05 c7 05 90 01 08 89 45 0c 8b 45 e8 01 45 0c ff 75 fc 8d 45 f4 50 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}