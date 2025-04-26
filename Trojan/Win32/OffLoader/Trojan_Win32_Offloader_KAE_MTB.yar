
rule Trojan_Win32_Offloader_KAE_MTB{
	meta:
		description = "Trojan:Win32/Offloader.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_80_0 = {2f 62 69 72 74 68 67 68 6f 73 74 2e 69 63 75 2f 77 69 6e 64 2e 70 68 70 } ///birthghost.icu/wind.php  5
		$a_80_1 = {2f 73 69 6c 65 6e 74 } ///silent  1
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*1) >=6
 
}