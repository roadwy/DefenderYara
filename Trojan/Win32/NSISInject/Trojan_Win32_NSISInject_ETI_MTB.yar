
rule Trojan_Win32_NSISInject_ETI_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.ETI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d8 59 59 6a 04 68 00 30 00 00 68 90 01 04 56 ff d7 90 00 } //1
		$a_01_1 = {6a 00 51 56 ff 75 e4 ff 34 18 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}