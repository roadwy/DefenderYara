
rule Trojan_Win32_Offloader_KAT_MTB{
	meta:
		description = "Trojan:Win32/Offloader.KAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_80_0 = {2f 6c 75 6d 62 65 72 63 61 72 65 2e 73 62 73 2f 63 61 72 2e 70 68 70 } ///lumbercare.sbs/car.php  10
		$a_80_1 = {2f 73 69 6c 65 6e 74 } ///silent  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}