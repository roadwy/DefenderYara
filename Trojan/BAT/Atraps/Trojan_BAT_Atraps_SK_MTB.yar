
rule Trojan_BAT_Atraps_SK_MTB{
	meta:
		description = "Trojan:BAT/Atraps.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 7b 0a 00 00 04 7b 25 00 00 04 07 17 58 0e 04 07 9a 05 6f ?? ?? ?? 06 07 9a 28 ?? ?? ?? 06 6f ?? ?? ?? 06 07 17 58 0b 07 6e 0e 04 8e 69 6a 32 cf } //2
		$a_01_1 = {42 55 4d 2e 65 78 65 } //2 BUM.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}