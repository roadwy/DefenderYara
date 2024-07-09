
rule Trojan_BAT_PureCrypter_PSIL_MTB{
	meta:
		description = "Trojan:BAT/PureCrypter.PSIL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 03 11 02 11 04 11 02 8e 69 5d 91 11 01 11 04 91 61 d2 6f ?? ?? ?? 0a 20 ?? ?? ?? 00 7e 07 00 00 04 7b 42 00 00 04 3a 26 ff ff ff 26 20 ?? ?? ?? 00 38 1b ff ff ff 28 17 00 00 06 72 79 00 00 70 6f ?? ?? ?? 0a 13 02 38 8d ff ff ff 11 03 28 18 00 00 06 13 05 38 ?? ?? ?? 00 dd a3 00 00 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}