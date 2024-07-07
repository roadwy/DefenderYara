
rule Trojan_Win32_Emotet_DAI_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 ff 15 90 01 04 6a 00 6a 00 ff 15 90 1b 00 6a 00 6a 00 ff 15 90 1b 00 6a 00 6a 00 ff 15 90 1b 00 6a 00 6a 00 ff 15 90 1b 00 8b 55 08 03 55 ec 33 c0 8a 02 8b 4d fc 03 4d f8 81 e1 ff 00 00 00 33 d2 8a 94 0d 90 01 04 33 c2 8b 4d 08 03 4d ec 88 01 90 00 } //1
		$a_00_1 = {6a 00 6a 00 ff d6 6a 00 6a 00 ff d6 6a 00 6a 00 ff d6 6a 00 6a 00 ff d6 6a 00 6a 00 ff d6 02 5c 24 14 8b 44 24 18 0f b6 d3 8a 4c 14 1c 30 0c 38 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}