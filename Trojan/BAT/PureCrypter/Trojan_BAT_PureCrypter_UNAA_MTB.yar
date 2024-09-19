
rule Trojan_BAT_PureCrypter_UNAA_MTB{
	meta:
		description = "Trojan:BAT/PureCrypter.UNAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 16 0c 38 19 00 00 00 06 07 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 08 18 58 0c 08 07 6f 0d 00 00 0a 3f } //4
		$a_01_1 = {47 65 74 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //1 GetByteArrayAsync
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}