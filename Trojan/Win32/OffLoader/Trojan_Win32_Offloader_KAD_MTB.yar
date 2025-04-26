
rule Trojan_Win32_Offloader_KAD_MTB{
	meta:
		description = "Trojan:Win32/Offloader.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_80_0 = {3a 2f 2f 74 6f 6f 74 68 70 61 73 74 65 74 68 69 6e 67 73 2e 78 79 7a 2f 79 61 73 2e 70 68 70 } //://toothpastethings.xyz/yas.php  2
		$a_80_1 = {2f 73 69 6c 65 6e 74 } ///silent  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1) >=3
 
}