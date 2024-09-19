
rule Trojan_Win32_Offloader_KAH_MTB{
	meta:
		description = "Trojan:Win32/Offloader.KAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {2f 66 6c 61 67 63 72 6f 77 2e 69 63 75 } ///flagcrow.icu  1
		$a_80_1 = {2f 73 69 6c 65 6e 74 } ///silent  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}