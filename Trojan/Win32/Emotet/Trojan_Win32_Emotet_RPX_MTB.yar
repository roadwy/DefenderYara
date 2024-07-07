
rule Trojan_Win32_Emotet_RPX_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 6a 00 6a 20 6a 04 6a 00 6a 00 68 00 00 00 40 68 90 01 04 ff d3 8b f0 c7 44 24 0c ff ff ff ff 83 fe ff 74 55 6a 02 6a 00 6a 00 56 ff 15 90 01 04 8d 54 24 10 6a 00 52 8d 44 24 14 6a 04 50 56 ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}