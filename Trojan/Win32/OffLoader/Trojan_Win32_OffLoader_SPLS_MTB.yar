
rule Trojan_Win32_OffLoader_SPLS_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.SPLS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_80_0 = {2f 2f 70 6f 69 73 6f 6e 68 6f 72 6e 2e 78 79 7a 2f 72 79 74 6f 2e 70 68 70 } ////poisonhorn.xyz/ryto.php  4
		$a_80_1 = {2f 73 69 6c 65 6e 74 } ///silent  1
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*1) >=5
 
}