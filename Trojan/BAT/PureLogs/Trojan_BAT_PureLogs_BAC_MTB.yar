
rule Trojan_BAT_PureLogs_BAC_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 0b 00 00 0a 7a 11 00 16 73 0d 00 00 0a 13 04 38 00 00 00 00 00 20 00 10 00 00 8d 0d 00 00 01 13 05 38 2d 00 00 00 11 04 11 05 16 11 05 8e 69 ?? ?? 00 00 0a 25 13 06 16 3d 05 00 00 00 38 1b 00 00 00 11 01 11 05 16 11 06 ?? ?? 00 00 0a 38 d3 ff ff ff 38 ce ff ff ff 38 e5 ff ff ff dd 41 00 00 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}