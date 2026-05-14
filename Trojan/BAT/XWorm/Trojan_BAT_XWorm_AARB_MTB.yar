
rule Trojan_BAT_XWorm_AARB_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AARB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 07 08 8f ?? 00 00 01 25 71 ?? 00 00 01 06 08 11 04 59 91 20 ae 00 00 00 61 d2 61 d2 81 ?? 00 00 01 1c 13 09 38 ?? ff ff ff d0 ?? ?? 00 06 26 08 11 05 32 cb } //5
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}