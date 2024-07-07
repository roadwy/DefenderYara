
rule Trojan_Win32_LegionLoader_AABX_MTB{
	meta:
		description = "Trojan:Win32/LegionLoader.AABX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4a 69 6f 61 66 75 61 69 6f 66 61 6f 66 73 } //1 Jioafuaiofaofs
		$a_01_1 = {4e 70 6f 61 64 70 6f 66 61 6a 69 6f 66 67 61 64 } //1 Npoadpofajiofgad
		$a_01_2 = {50 6f 61 66 6f 61 64 6a 66 69 61 64 6a } //1 Poafoadjfiadj
		$a_01_3 = {51 52 63 6f 64 65 5f 65 6e 63 6f 64 65 53 74 72 69 6e 67 } //1 QRcode_encodeString
		$a_01_4 = {55 49 61 69 61 6f 67 66 69 61 73 64 6a 67 61 73 64 67 6a } //1 UIaiaogfiasdjgasdgj
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}