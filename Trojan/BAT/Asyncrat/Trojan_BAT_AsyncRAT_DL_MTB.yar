
rule Trojan_BAT_AsyncRAT_DL_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 7e 07 0f 00 04 02 07 6f 63 00 00 0a 7e aa 0e 00 04 07 7e aa 0e 00 04 8e 69 5d 91 61 28 6c 2f 00 06 28 71 2f 00 06 26 07 17 58 0b 07 02 6f 64 00 00 0a 32 c6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}