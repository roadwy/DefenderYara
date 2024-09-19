
rule Trojan_BAT_Lokibot_RUAA_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.RUAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 0b 11 0b 11 07 28 ?? 00 00 06 13 0c 73 ?? 00 00 06 13 0d 11 0d 72 ?? ?? 00 70 1d 8d ?? 00 00 01 25 16 72 ?? ?? 00 70 a2 25 17 72 ?? ?? 00 70 a2 25 18 11 0c a2 25 19 17 8c ?? 00 00 01 a2 25 1a 16 8c ?? 00 00 01 a2 25 1b } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}