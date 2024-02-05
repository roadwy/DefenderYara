
rule Trojan_Win32_DCRat_RPX_MTB{
	meta:
		description = "Trojan:Win32/DCRat.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 8d ec aa fe ff 83 c1 01 89 8d ec aa fe ff 8b 95 ec aa fe ff 3b 95 f4 aa fe ff 73 29 8b 85 ec aa fe ff c1 e0 00 8d 8d f8 aa fe ff 0f b6 14 08 f7 da 8b 85 ec aa fe ff c1 e0 00 8d 8d f8 aa fe ff 88 14 08 eb ba } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_DCRat_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/DCRat.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 85 f8 aa fe ff e8 c6 85 f9 aa fe ff 88 c6 85 fa aa fe ff f7 c6 85 fb aa fe ff 00 c6 85 fc aa fe ff 00 c6 85 fd aa fe ff 88 c6 85 fe aa fe ff f7 c6 85 ff aa fe ff 00 c6 85 00 ab fe ff 00 c6 85 01 ab fe ff 00 c6 85 02 ab fe ff 97 c6 85 03 ab fe ff f2 c6 85 04 ab fe ff a3 c6 85 05 ab fe ff 74 } //00 00 
	condition:
		any of ($a_*)
 
}