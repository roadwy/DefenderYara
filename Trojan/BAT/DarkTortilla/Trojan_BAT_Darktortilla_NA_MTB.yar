
rule Trojan_BAT_Darktortilla_NA_MTB{
	meta:
		description = "Trojan:BAT/Darktortilla.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {93 61 1f 5c 5f 9d fe 02 2b 01 17 0a 06 2c 05 19 13 06 2b 87 18 2b f9 } //2
		$a_01_1 = {91 61 20 c7 00 00 00 5f 9c 2c 05 17 13 04 2b a3 16 } //1
		$a_01_2 = {91 61 1f 4e 5f 9c 2d 09 1f 0a 13 08 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}