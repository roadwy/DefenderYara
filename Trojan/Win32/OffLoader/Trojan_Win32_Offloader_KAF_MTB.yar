
rule Trojan_Win32_Offloader_KAF_MTB{
	meta:
		description = "Trojan:Win32/Offloader.KAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_80_0 = {2f 71 75 69 63 6b 73 61 6e 64 73 68 61 70 65 2e 69 63 75 2f 69 74 69 73 2e 70 68 70 } ///quicksandshape.icu/itis.php  5
		$a_80_1 = {2f 73 69 6c 65 6e 74 } ///silent  1
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*1) >=6
 
}