
rule Trojan_BAT_Redline_NIT_MTB{
	meta:
		description = "Trojan:BAT/Redline.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 05 9a 13 06 00 06 11 06 6f ?? 00 00 06 2c 03 16 2b 03 17 2b 00 2d 08 06 6f ?? 00 00 06 2b 06 18 28 ?? 03 00 06 13 07 11 07 2c 03 16 2b 03 17 2b 00 2d 0a 00 16 28 ?? 03 00 06 0b 2b 14 00 11 05 16 28 ?? 03 00 06 58 13 05 11 05 11 04 8e 69 32 ac } //2
		$a_01_1 = {47 65 74 41 6c 6c 4e 65 74 77 6f 72 6b 49 6e 74 65 72 66 61 63 65 73 } //1 GetAllNetworkInterfaces
		$a_01_2 = {43 6c 69 65 6e 74 43 72 65 64 65 6e 74 69 61 6c 73 } //1 ClientCredentials
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}