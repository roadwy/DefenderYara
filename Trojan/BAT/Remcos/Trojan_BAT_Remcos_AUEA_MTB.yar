
rule Trojan_BAT_Remcos_AUEA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AUEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {60 0d 03 19 8d ?? 00 00 01 25 16 09 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 09 1e 63 20 ff 00 00 00 5f d2 9c 25 18 09 20 ff 00 00 00 5f d2 9c } //3
		$a_03_1 = {01 25 16 0f 01 28 ?? 00 00 0a 9c 25 17 0f 01 28 ?? 00 00 0a 9c 25 18 0f 01 28 ?? 00 00 0a 9c 04 28 ?? 00 00 2b 6f ?? 00 00 0a 00 2a } //2
		$a_01_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}