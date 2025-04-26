
rule Trojan_Win32_Offloader_KAB_MTB{
	meta:
		description = "Trojan:Win32/Offloader.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_80_0 = {3a 2f 2f 62 61 67 6f 66 66 65 72 2e 73 69 74 65 } //://bagoffer.site  2
		$a_80_1 = {3a 2f 2f 6e 6f 74 65 66 72 69 65 6e 64 73 2e 73 69 74 65 2f 62 63 68 2e 70 68 70 } //://notefriends.site/bch.php  2
		$a_80_2 = {2f 73 69 6c 65 6e 74 } ///silent  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1) >=5
 
}