
rule Trojan_BAT_Androm_AADX_MTB{
	meta:
		description = "Trojan:BAT/Androm.AADX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 02 11 0a 11 03 18 28 ?? 00 00 06 1f 10 28 ?? 00 00 06 6f ?? 00 00 0a 20 00 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 3a ?? ff ff ff 26 20 00 00 00 00 38 } //4
		$a_01_1 = {51 00 6f 00 6d 00 65 00 64 00 73 00 61 00 6a 00 7a 00 69 00 } //1 Qomedsajzi
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}