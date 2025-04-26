
rule Trojan_Win32_VBClone_GTT_MTB{
	meta:
		description = "Trojan:Win32/VBClone.GTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 33 d8 44 87 17 37 f3 5f } //5
		$a_03_1 = {ff cc 31 00 04 8c 2d ?? ?? ?? ?? 56 43 99 ff } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}