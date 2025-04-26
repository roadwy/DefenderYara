
rule Trojan_Win32_OffLoader_SBLS_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.SBLS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_80_0 = {2f 2f 67 72 61 69 6e 69 6e 6b 2e 77 65 62 73 69 74 65 2f 68 69 6f 2e 70 68 70 } ////grainink.website/hio.php  4
		$a_80_1 = {2f 73 69 6c 65 6e 74 } ///silent  1
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*1) >=5
 
}