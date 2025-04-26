
rule Trojan_BAT_Remcos_SUDA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.SUDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 16 0f 00 20 ?? ?? ?? 00 20 ?? ?? ?? 00 28 ?? ?? ?? 06 16 61 d2 9c 25 17 0f 00 28 ?? 00 00 0a 16 60 d2 9c 25 18 0f 00 28 ?? 01 00 0a 20 ff 00 00 00 5f d2 9c 13 08 17 13 13 2b 83 } //2
		$a_03_1 = {04 19 8d b0 00 00 01 25 16 08 9c 25 17 09 9c 25 18 11 04 9c 6f ?? 01 00 0a 19 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}