
rule Trojan_Win32_Offloader_KAV_MTB{
	meta:
		description = "Trojan:Win32/Offloader.KAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_80_0 = {2f 64 6f 67 64 65 63 69 73 69 6f 6e 2e 63 66 64 2f 62 61 72 2e 70 68 70 } ///dogdecision.cfd/bar.php  10
		$a_80_1 = {2f 73 69 6c 65 6e 74 } ///silent  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}