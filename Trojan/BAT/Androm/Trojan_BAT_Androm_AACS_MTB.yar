
rule Trojan_BAT_Androm_AACS_MTB{
	meta:
		description = "Trojan:BAT/Androm.AACS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 54 4f 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //2 DTO.Properties.Resources
		$a_01_1 = {39 31 31 66 30 30 36 31 2d 65 30 36 31 2d 34 30 62 32 2d 38 30 32 31 2d 32 61 32 65 34 61 34 35 37 33 66 63 } //2 911f0061-e061-40b2-8021-2a2e4a4573fc
		$a_01_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}