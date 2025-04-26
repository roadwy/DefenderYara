
rule Trojan_Win32_Injector_MRVF_MTB{
	meta:
		description = "Trojan:Win32/Injector.MRVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b 33 71 b5 e2 d6 34 d1 ed } //1
		$a_01_1 = {b7 04 00 ff 04 28 ff 05 01 00 24 02 00 0d 14 00 03 00 08 28 ff 0d 50 00 04 00 6c 00 ff 5e 18 00 04 00 71 dc } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}