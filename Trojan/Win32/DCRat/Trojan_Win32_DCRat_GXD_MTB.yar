
rule Trojan_Win32_DCRat_GXD_MTB{
	meta:
		description = "Trojan:Win32/DCRat.GXD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 4b 4a 3f 4b 32 3f 83 c4 14 } //5
		$a_03_1 = {43 42 43 33 36 3d ?? ?? ?? ?? 3f 01 00 5f } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}