
rule Trojan_BAT_NanoCore_MR_MTB{
	meta:
		description = "Trojan:BAT/NanoCore.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {0a 16 0b 16 0c 2b 1b 02 08 02 08 91 06 07 25 17 58 0b 91 61 d2 9c 07 06 8e 69 33 02 16 0b 08 17 58 0c 08 02 8e 69 32 df 02 2a 90 09 0b 00 28 90 01 04 03 6f 90 00 } //1
		$a_02_1 = {0c 06 07 6f 90 01 04 08 6f 90 01 04 0d 90 09 62 00 7e 90 01 13 0a 28 90 01 04 1f 22 8d 90 01 04 25 d0 90 01 18 0b 28 90 01 04 1f 0a 8d 90 01 04 25 d0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}