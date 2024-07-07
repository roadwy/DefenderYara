
rule Trojan_Win32_DelfInject_AZ_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {d0 cc 8a 04 33 } //1
		$a_01_1 = {32 07 88 07 47 4b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}