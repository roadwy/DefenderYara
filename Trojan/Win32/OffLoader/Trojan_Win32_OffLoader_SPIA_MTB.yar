
rule Trojan_Win32_OffLoader_SPIA_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.SPIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_80_0 = {2f 63 75 72 76 65 74 72 61 69 6c 2e 78 79 7a 2f 6e 75 65 2e 70 68 70 3f } ///curvetrail.xyz/nue.php?  4
		$a_80_1 = {2f 73 69 6c 65 6e 74 } ///silent  1
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*1) >=5
 
}