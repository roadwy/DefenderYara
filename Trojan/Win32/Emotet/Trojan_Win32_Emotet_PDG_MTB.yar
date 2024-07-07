
rule Trojan_Win32_Emotet_PDG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 d3 03 c2 99 b9 90 01 04 f7 f9 8b 44 24 90 01 01 40 83 c4 0c 89 44 24 90 01 01 0f b6 54 14 90 01 01 30 50 90 00 } //1
		$a_81_1 = {43 6c 45 75 30 76 51 52 55 36 6a 56 46 55 62 35 37 69 7a 4a 30 41 54 75 39 74 67 73 30 4b 31 43 4f 44 41 4b 6d 63 5a 53 45 33 38 56 4b 51 4a } //1 ClEu0vQRU6jVFUb57izJ0ATu9tgs0K1CODAKmcZSE38VKQJ
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}