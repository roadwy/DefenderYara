
rule Trojan_Win32_Offloader_KAO_MTB{
	meta:
		description = "Trojan:Win32/Offloader.KAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {64 6f 63 74 6f 72 66 72 61 6d 65 2e 73 62 73 2f 61 6e 6a 2e 70 68 70 } //doctorframe.sbs/anj.php  1
		$a_80_1 = {2f 73 69 6c 65 6e 74 } ///silent  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}