
rule Trojan_Win32_Offloader_KAM_MTB{
	meta:
		description = "Trojan:Win32/Offloader.KAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {2f 74 68 65 6f 72 79 71 75 61 72 74 65 72 2e 63 66 64 2f 68 75 6c 2e 70 68 70 } ///theoryquarter.cfd/hul.php  1
		$a_80_1 = {2f 73 69 6c 65 6e 74 } ///silent  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}