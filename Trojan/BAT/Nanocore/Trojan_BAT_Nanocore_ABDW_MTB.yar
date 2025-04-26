
rule Trojan_BAT_Nanocore_ABDW_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABDW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 2b 00 06 2a 90 0a 10 00 02 28 ?? ?? ?? 0a 28 } //2
		$a_03_1 = {01 25 16 08 a2 25 0d 14 14 17 8d ?? ?? ?? 01 25 16 17 9c 25 13 04 90 0a 33 00 0b 07 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 0c 28 ?? ?? ?? 0a 14 72 ?? ?? ?? 70 17 8d } //2
		$a_01_2 = {53 00 79 00 73 00 74 00 65 00 6d 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 SystemManager.Resources
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}