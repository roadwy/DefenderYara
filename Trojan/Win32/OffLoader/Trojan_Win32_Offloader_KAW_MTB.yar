
rule Trojan_Win32_Offloader_KAW_MTB{
	meta:
		description = "Trojan:Win32/Offloader.KAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_80_0 = {2f 73 68 61 64 65 6d 6f 6d 2e 69 63 75 2f 6e 32 35 2e 70 68 70 } ///shademom.icu/n25.php  10
		$a_80_1 = {2f 73 69 6c 65 6e 74 } ///silent  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}