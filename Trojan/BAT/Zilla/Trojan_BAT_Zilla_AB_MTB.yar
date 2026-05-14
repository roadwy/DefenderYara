
rule Trojan_BAT_Zilla_AB_MTB{
	meta:
		description = "Trojan:BAT/Zilla.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 07 6f 12 00 00 0a a5 11 00 00 01 0c 08 0a 7e 02 00 00 04 12 02 28 13 00 00 0a 28 14 00 00 0a 6f 15 00 00 0a 0d 09 28 16 00 00 0a 72 21 00 00 70 28 02 00 00 06 13 04 7e 01 00 00 04 72 69 00 00 70 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Zilla_AB_MTB_2{
	meta:
		description = "Trojan:BAT/Zilla.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 06 16 11 06 8e 69 6f ?? 00 00 0a 13 08 2b 1c 11 04 11 06 16 11 08 6f ?? 00 00 0a 11 05 11 06 16 11 06 8e 69 6f ?? 00 00 0a 13 08 11 08 16 30 df 11 04 6f ?? 00 00 0a 7e 01 00 00 04 28 01 00 00 06 28 02 00 00 06 0a de 0c 11 04 2c 07 11 04 6f ?? 00 00 0a dc d0 0f 00 00 01 } //6
		$a_81_1 = {47 5a 69 70 53 74 72 65 61 6d } //2 GZipStream
		$a_81_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //2 MemoryStream
		$a_81_3 = {53 79 73 74 65 6d 2e 49 4f 2e 43 6f 6d 70 72 65 73 73 69 6f 6e } //2 System.IO.Compression
	condition:
		((#a_03_0  & 1)*6+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2) >=12
 
}