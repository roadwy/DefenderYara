
rule Trojan_Win32_DllInject_XZ_MTB{
	meta:
		description = "Trojan:Win32/DllInject.XZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {32 05 14 9b 4f 00 88 01 41 8a 01 84 c0 75 f1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}