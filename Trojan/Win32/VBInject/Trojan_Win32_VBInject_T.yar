
rule Trojan_Win32_VBInject_T{
	meta:
		description = "Trojan:Win32/VBInject.T,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 40 00 00 e8 ?? ?? f8 ff 66 3d ff ff 74 05 e8 ?? ff ff ff 56 56 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}