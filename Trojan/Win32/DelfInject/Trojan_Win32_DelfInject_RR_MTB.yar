
rule Trojan_Win32_DelfInject_RR_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 ca 00 02 00 00 a9 00 00 00 20 74 } //1
		$a_03_1 = {31 d1 89 c8 6a 00 6a 01 a1 90 02 05 50 ff 15 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}