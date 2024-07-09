
rule Trojan_BAT_Webshell_AW_MTB{
	meta:
		description = "Trojan:BAT/Webshell.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 05 11 05 02 6f 16 00 00 0a 6f 4c 00 00 0a 26 11 05 11 04 6f 4c 00 00 0a 26 11 05 09 6f 4c 00 00 0a 26 11 05 6f 4d 00 00 0a 26 11 04 6f 4e 00 00 0a 13 06 02 6f 16 00 00 0a 6f 4f 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Webshell_AW_MTB_2{
	meta:
		description = "Trojan:BAT/Webshell.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {72 9f 00 00 70 d0 24 00 00 01 28 ?? ?? ?? 0a 72 af 00 00 70 17 8d ?? ?? ?? 01 13 08 11 08 16 d0 01 00 00 1b 28 ?? ?? ?? 0a a2 11 08 28 ?? ?? ?? 0a 14 17 8d ?? ?? ?? 01 13 09 11 09 16 09 a2 11 09 } //2
		$a_01_1 = {5f 5f 52 65 6e 64 65 72 5f 5f 63 6f 6e 74 72 6f 6c 31 } //1 __Render__control1
		$a_01_2 = {70 00 61 00 79 00 6c 00 6f 00 61 00 64 00 } //1 payload
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}