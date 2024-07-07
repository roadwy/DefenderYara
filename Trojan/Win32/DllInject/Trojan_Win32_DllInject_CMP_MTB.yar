
rule Trojan_Win32_DllInject_CMP_MTB{
	meta:
		description = "Trojan:Win32/DllInject.CMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {46 8a 46 ff 90 01 01 56 83 c4 90 01 01 32 02 88 07 47 90 01 01 89 c0 42 83 ec 04 c7 90 01 06 83 c4 04 49 89 c0 85 c9 75 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}