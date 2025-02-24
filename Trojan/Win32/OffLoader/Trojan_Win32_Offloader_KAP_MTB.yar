
rule Trojan_Win32_Offloader_KAP_MTB{
	meta:
		description = "Trojan:Win32/Offloader.KAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_80_0 = {2f 70 6c 61 79 67 72 6f 75 6e 64 73 74 6f 6e 65 2e 63 66 64 2f 6a 75 69 2e 70 68 70 } ///playgroundstone.cfd/jui.php  10
		$a_80_1 = {2f 73 69 6c 65 6e 74 } ///silent  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}