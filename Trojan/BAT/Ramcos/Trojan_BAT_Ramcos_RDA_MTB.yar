
rule Trojan_BAT_Ramcos_RDA_MTB{
	meta:
		description = "Trojan:BAT/Ramcos.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 00 39 00 32 00 2e 00 32 00 32 00 37 00 2e 00 31 00 38 00 33 00 2e 00 31 00 35 00 32 00 } //1 192.227.183.152
		$a_03_1 = {06 6f 2d 00 00 0a 0b 07 d2 13 07 12 07 72 ?? ?? ?? ?? 28 2e 00 00 0a 13 04 11 06 07 11 04 a2 08 11 04 07 d2 6f 2f 00 00 0a 08 11 04 6f 30 00 00 0a 07 d2 6f 2f 00 00 0a 06 6f 31 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}