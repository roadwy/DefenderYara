
rule Trojan_BAT_NjRAT_SARA_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.SARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 08 6f ?? ?? ?? 0a 00 11 04 04 6f ?? ?? ?? 0a 00 11 04 05 6f ?? ?? ?? 0a 00 11 04 6f ?? ?? ?? 0a 0a 06 02 16 02 8e b7 6f ?? ?? ?? 0a 0d 11 04 6f ?? ?? ?? 0a 00 09 13 05 } //2
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}