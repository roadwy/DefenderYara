
rule Trojan_Win32_Offloader_KAU_MTB{
	meta:
		description = "Trojan:Win32/Offloader.KAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_80_0 = {2f 74 72 75 63 6b 73 73 74 69 63 6b 2e 69 63 75 2f 64 6f 6e 2e 70 68 70 } ///trucksstick.icu/don.php  10
		$a_80_1 = {2f 73 69 6c 65 6e 74 } ///silent  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}