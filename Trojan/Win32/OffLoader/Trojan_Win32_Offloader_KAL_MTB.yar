
rule Trojan_Win32_Offloader_KAL_MTB{
	meta:
		description = "Trojan:Win32/Offloader.KAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {2f 61 63 68 69 65 76 65 72 61 72 74 2e 73 70 61 63 65 2f 69 73 74 2e 70 68 70 } ///achieverart.space/ist.php  1
		$a_80_1 = {2f 73 69 6c 65 6e 74 } ///silent  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}