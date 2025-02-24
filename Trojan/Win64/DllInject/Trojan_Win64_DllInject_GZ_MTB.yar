
rule Trojan_Win64_DllInject_GZ_MTB{
	meta:
		description = "Trojan:Win64/DllInject.GZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 44 0d 87 43 32 04 13 41 88 02 49 ff c2 41 81 f9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}