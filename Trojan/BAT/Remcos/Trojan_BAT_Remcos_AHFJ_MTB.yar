
rule Trojan_BAT_Remcos_AHFJ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AHFJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 08 2b 1d 07 06 11 08 9a 1f 10 28 ?? ?? ?? 0a 8c 54 00 00 01 6f ?? ?? ?? 0a 26 11 08 17 58 13 08 11 08 } //2
		$a_01_1 = {4d 00 69 00 6c 00 6c 00 } //1 Mill
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}