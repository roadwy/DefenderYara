
rule Trojan_BAT_Snakekeylogger_UAGA_MTB{
	meta:
		description = "Trojan:BAT/Snakekeylogger.UAGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 11 05 6e 11 08 6a 59 d4 11 04 1e 11 08 59 1e 5a 1f 3f 5f 64 20 ff 00 00 00 6a 5f d2 9c 11 08 17 59 13 08 11 08 16 3d d4 ff ff ff } //1
		$a_01_1 = {4b 69 6e 6f 6d 61 6e 69 61 6b 20 4c 69 62 72 61 72 79 } //1 Kinomaniak Library
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}