
rule Trojan_BAT_Netwire_NTW_MTB{
	meta:
		description = "Trojan:BAT/Netwire.NTW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {08 09 16 20 00 10 00 00 6f ?? ?? ?? 0a 13 05 11 05 16 fe 02 13 06 11 06 2c 0e 00 11 04 09 16 11 05 6f ?? ?? ?? 0a 00 00 00 11 05 16 fe 02 13 07 11 07 2d cb } //1
		$a_01_1 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_01_2 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //1 CompressionMode
		$a_01_3 = {44 65 66 65 72 72 65 64 44 69 73 70 6f 73 61 62 6c 65 } //1 DeferredDisposable
		$a_01_4 = {42 00 38 00 44 00 32 00 35 00 54 00 } //1 B8D25T
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}